package radius

import (
	"fmt"
	"huawei-portal-go/internal/models"
	"strconv"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"gorm.io/gorm"
)

type RadiusService struct {
	DB *gorm.DB
}

func cleanMAC(mac string) string {
	s := strings.ReplaceAll(mac, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ".", "")
	return strings.ToLower(s)
}

func extractAPMAC(calledStationID string) string {
	if calledStationID == "" { return "" }
	parts := strings.Split(calledStationID, ":")
	if len(parts) > 0 {
		mac := cleanMAC(parts[0])
		if len(mac) == 12 { return mac }
	}
	return ""
}

func getValidityDuration(db *gorm.DB) time.Duration {
	var conf models.SystemConfig
	if err := db.Where("`key` = ?", "auth_validity_hours").First(&conf).Error; err != nil {
		return 24 * time.Hour
	}
	h, _ := strconv.Atoi(conf.Value)
	if h <= 0 { h = 24 }
	return time.Duration(h) * time.Hour
}

// 【关键逻辑】智能查找用户
// 优先级：手动添加(白名单) > 网页认证用户 > 自动生成用户
func findUser(db *gorm.DB, radiusUser, radiusMac string) (*models.Guest, error) {
	var guests []models.Guest
	cleanUser := cleanMAC(radiusUser) // RADIUS 用户名 (可能是MAC)
	cleanMacInput := cleanMAC(radiusMac) // RADIUS MAC地址
	
	// 宽泛查找：匹配用户名 OR 匹配MAC
	// 注意：MySQL的 REPLACE 语法用于处理数据库中格式不统一的 MAC
	err := db.Where("(username = ? OR REPLACE(REPLACE(user_mac, ':', ''), '-', '') = ? OR REPLACE(REPLACE(user_mac, ':', ''), '-', '') = ?) AND expires_at > ?", 
		radiusUser, cleanUser, cleanMacInput, time.Now()).
		Find(&guests).Error
		
	if err != nil || len(guests) == 0 {
		return nil, err
	}

	// 内存打分，选出最佳匹配
	var best *models.Guest
	bestScore := -1

	for i := range guests {
		u := &guests[i]
		score := 0
		
		// 1. 白名单用户 (手动添加的) - 优先级最高
		if u.SessionID == "MANUAL" {
			score = 100 
		} else if strings.HasPrefix(u.SessionID, "HTTP-") {
			// 2. 网页认证用户 - 优先级次之
			score = 50
		} else {
			// 3. 自动生成的临时用户 - 优先级最低
			score = 1
		}

		// 同等优先级下，取最近登录的
		if score > bestScore {
			best = u
			bestScore = score
		} else if score == bestScore {
			if u.LoginTime.After(best.LoginTime) {
				best = u
			}
		}
	}
	
	return best, nil
}

func (s *RadiusService) HandleAuth(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	mac := rfc2865.CallingStationID_GetString(r.Packet)
	apMac := extractAPMAC(rfc2865.CalledStationID_GetString(r.Packet))
	
	fmt.Printf("[RADIUS Auth] User: %s | MAC: %s | AP: %s\n", username, mac, apMac)

	code := radius.CodeAccessReject
	
	// 使用智能查找
	guest, err := findUser(s.DB, username, mac)

	if err == nil && guest != nil {
		fmt.Printf("[RADIUS Auth] ✅ Success (Matched: %s, Type: %s)\n", guest.Username, guest.SessionID)
		code = radius.CodeAccessAccept

		updates := map[string]interface{}{}
		if ip := rfc2865.FramedIPAddress_Get(r.Packet); ip != nil && ip.String() != "0.0.0.0" {
			updates["user_ip"] = ip.String()
		}
		if apMac != "" { updates["apmac"] = apMac }
		if guest.UserMAC == "" && mac != "" { updates["user_mac"] = mac } // 补全MAC
		
		updates["is_online"] = true
		updates["login_time"] = time.Now()

		s.DB.Model(guest).Updates(updates)
	} else {
		// 备用：短信验证码
		var vc models.VerificationCode
		if err := s.DB.Where("phone_number = ? AND code = ? AND is_used = 0", username, rfc2865.UserPassword_GetString(r.Packet)).First(&vc).Error; err == nil {
			code = radius.CodeAccessAccept
		}
	}
	w.Write(r.Response(code))
}

func (s *RadiusService) HandleAcct(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	mac := cleanMAC(rfc2865.CallingStationID_GetString(r.Packet))
	apMac := extractAPMAC(rfc2865.CalledStationID_GetString(r.Packet))
	userIP := ""
	if ip := rfc2865.FramedIPAddress_Get(r.Packet); ip != nil { userIP = ip.String() }

	statusType := r.Packet.Get(rfc2866.AcctStatusType_Type)
	statusVal := 0
	if statusType != nil { val, _ := radius.Integer(statusType); statusVal = int(val) }

	// 智能查找：确保记账数据更新到正确的账号上
	guest, err := findUser(s.DB, username, mac)

	switch statusVal {
	case 1, 3: // Start or Interim
		action := "Start"
		if statusVal == 3 { action = "Interim" }
		fmt.Printf("[RADIUS Acct] %s: %s | IP: %s\n", action, username, userIP)
		
		if err == nil && guest != nil {
			// 【修复】更新到现有的白名单/网页账号
			fmt.Printf("   -> Updating User: %s (IP: %s)\n", guest.Username, userIP)
			updates := map[string]interface{}{"login_time": time.Now(), "is_online": true}
			if userIP != "" && userIP != "0.0.0.0" { updates["user_ip"] = userIP }
			if apMac != "" { updates["apmac"] = apMac }
			if guest.UserMAC == "" && mac != "" { updates["user_mac"] = mac }
			s.DB.Model(guest).Updates(updates)
		} else {
			// 只有找不到任何匹配时，才创建临时账号 (这种情况应该很少见)
			fmt.Printf("   -> New Guest (Auto): %s\n", username)
			s.DB.Create(&models.Guest{
				Username: username, UserIP: userIP, UserMAC: mac, APMAC: apMac, 
				LoginTime: time.Now(), SessionID: "RADIUS-AUTO", 
				IsOnline: true, ExpiresAt: time.Now().Add(24 * time.Hour),
			})
		}

	case 2: // Stop
		fmt.Printf("[RADIUS Acct] Stop: %s\n", username)
		auditLog := models.AuditLog{Username: username, UserIP: userIP, UserMAC: mac, APMAC: apMac, Action: "LOGOUT", Result: "SUCCESS", CreatedAt: time.Now()}
		
		if guest != nil {
			auditLog.Username = guest.Username // 修正为真实账号
			auditLog.RealName = guest.RealName
			s.DB.Model(guest).Update("is_online", false)
		} else {
			s.DB.Model(&models.Guest{}).Where("username = ? OR user_mac = ?", username, mac).Update("is_online", false)
		}
		s.DB.Create(&auditLog)
		
	case 7, 8: // On/Off
		s.DB.Exec("DELETE FROM guests WHERE session_id = 'RADIUS-AUTO'")
		s.DB.Model(&models.Guest{}).Update("is_online", false)
	}
	w.Write(r.Response(radius.CodeAccountingResponse))
}

func StartRadiusServer(db *gorm.DB, secret string) {
	handler := &RadiusService{DB: db}
	server := radius.PacketServer{Addr: ":1812", Handler: radius.HandlerFunc(handler.HandleAuth), SecretSource: radius.StaticSecretSource([]byte(secret))}
	server.ListenAndServe()
}
func StartAcctServer(db *gorm.DB, secret string) {
	handler := &RadiusService{DB: db}
	server := radius.PacketServer{Addr: ":1813", Handler: radius.HandlerFunc(handler.HandleAcct), SecretSource: radius.StaticSecretSource([]byte(secret))}
	server.ListenAndServe()
}
