package service

import (
	"errors"
	"fmt"
	"huawei-portal-go/internal/models"
	"huawei-portal-go/internal/radius"
	"huawei-portal-go/internal/portal"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	DB *gorm.DB
}

func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{DB: db}
}

// ---------------- 📊 Pro 版图表统计函数 ----------------
func (s *AuthService) Get24HourTrend() (map[string]interface{}, error) {
	type Result struct { HourStr string; Total int; Success int }
	var results []Result
	sql := "SELECT DATE_FORMAT(created_at, '%H:00') as hour_str, COUNT(*) as total, SUM(CASE WHEN result='SUCCESS' THEN 1 ELSE 0 END) as success FROM audit_logs WHERE action='LOGIN' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY hour_str ORDER BY MIN(created_at)"
	if err := s.DB.Raw(sql).Scan(&results).Error; err != nil { return nil, err }
	hours := []string{}; totalData := []int{}; successData := []int{}
	for _, r := range results { hours = append(hours, r.HourStr); totalData = append(totalData, r.Total); successData = append(successData, r.Success) }
	return map[string]interface{}{"hours": hours, "total": totalData, "success": successData}, nil
}
func (s *AuthService) GetFailureAnalysis() ([]map[string]interface{}, error) {
	type Result struct { Message string; Count int }
	var results []Result
	sql := "SELECT message, COUNT(*) as count FROM audit_logs WHERE action='LOGIN' AND result!='SUCCESS' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY message ORDER BY count DESC LIMIT 5"
	if err := s.DB.Raw(sql).Scan(&results).Error; err != nil { return nil, err }
	data := []map[string]interface{}{}
	for _, r := range results {
		msg := r.Message
		if strings.Contains(msg, "password") { msg = "密码错误" }
		if strings.Contains(msg, "limit") || strings.Contains(msg, "超限") { msg = "设备超限" }
		if strings.Contains(msg, "exist") { msg = "用户已存在" }
		data = append(data, map[string]interface{}{"name": msg, "value": r.Count})
	}
	if len(data) == 0 { data = append(data, map[string]interface{}{"name": "无异常", "value": 0}) }
	return data, nil
}
func (s *AuthService) GetTopAPs() (map[string]interface{}, error) {
	type Result struct { APMAC string; Count int }
	var results []Result
	sql := "SELECT apmac, COUNT(*) as count FROM guests WHERE is_online=true GROUP BY apmac ORDER BY count DESC LIMIT 5"
	if err := s.DB.Raw(sql).Scan(&results).Error; err != nil { return nil, err }
	aps := []string{}; counts := []int{}
	for _, r := range results { n := r.APMAC; if n == "" { n = "未知AP" }; aps = append(aps, n); counts = append(counts, r.Count) }
	return map[string]interface{}{"aps": aps, "counts": counts}, nil
}

// ---------------- 核心业务逻辑 ----------------

// 【新增】MAC 必填校验 + 3台限制
func (s *AuthService) ManualAddUser(username, realName, mac string, hours int) error {
	// 1. 必填校验
	if username == "" { return errors.New("账号不能为空") }
	if mac == "" { return errors.New("MAC 地址不能为空 (用于绑定设备)") }

	// 2. 查重 (同账号同MAC不允许重复添加)
	var dup int64
	s.DB.Model(&models.Guest{}).Where("username = ? AND user_mac = ?", username, mac).Count(&dup)
	if dup > 0 { return errors.New("该账号的此 MAC 设备已存在") }

	// 3. 查限额 (总数 < 3)
	var count int64
	s.DB.Model(&models.Guest{}).Where("username = ? AND expires_at > ?", username, time.Now()).Count(&count)
	if count >= 3 { 
		return fmt.Errorf("账号限额已满 (当前 %d 条有效记录，上限 3 条)", count) 
	}

	if hours <= 0 { hours = 24 }
	return s.DB.Create(&models.Guest{
		Username: username, RealName: realName, UserMAC: mac, 
		LoginTime: time.Now(), IsOnline: false, SessionID: "MANUAL", 
		ExpiresAt: time.Now().Add(time.Duration(hours) * time.Hour),
	}).Error
}

func (s *AuthService) VerifyAdminPassword(username, password string) bool {
	var admin models.Admin
	if err := s.DB.Where("username = ?", username).First(&admin).Error; err != nil { return false }
	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) == nil { return true }
	if admin.Password == password {
		h, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		s.DB.Model(&admin).Update("password", string(h)); return true
	}
	return false
}
func (s *AuthService) UpdatePassword(username, oldPwd, newPwd string) error {
	if !s.VerifyAdminPassword(username, oldPwd) { return errors.New("原密码错误") }
	h, err := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost); if err != nil { return err }
	return s.DB.Model(&models.Admin{}).Where("username = ?", username).Update("password", string(h)).Error
}
func (s *AuthService) StartCleaner() { go func() { for range time.Tick(1 * time.Minute) { s.cleanExpiredUsers() } }() }
func (s *AuthService) cleanExpiredUsers() {
	var expired []models.Guest
	s.DB.Where("is_online = ? AND expires_at < ?", true, time.Now()).Find(&expired)
	for _, u := range expired {
		if u.APMAC != "" { ac, _ := s.getACConfig(u.APMAC); go radius.SendDisconnect(ac.ACIP, ac.ACSecret, u.Username, u.UserMAC, u.UserIP) }
		s.DB.Model(&u).Update("is_online", false)
		s.logAudit(u.Username, u.RealName, u.UserIP, u.UserMAC, u.APMAC, "SYSTEM", "EXPIRE", "SUCCESS", "Auto Expired")
	}
}
func (s *AuthService) CheckOnline(userIP, userMAC string) (*models.Guest, error) {
	var guest models.Guest
	if err := s.DB.Where("user_ip = ? AND is_online = ? AND expires_at > ?", userIP, true, time.Now()).Limit(1).Find(&guest).Error; err == nil && guest.ID > 0 { return &guest, nil }
	if userMAC != "" {
		if err := s.DB.Where("(user_mac = ? OR REPLACE(REPLACE(user_mac, ':', ''), '-', '') = ?) AND is_online = ? AND expires_at > ?", userMAC, cleanMAC(userMAC), true, time.Now()).First(&guest).Error; err == nil {
			if guest.UserIP != userIP { s.DB.Model(&guest).Update("user_ip", userIP); guest.UserIP = userIP }
			return &guest, nil
		}
	}
	return nil, errors.New("not found")
}
func (s *AuthService) ManualLogout(target string) error {
	var guest models.Guest
	if err := s.DB.Where("user_mac = ? OR user_ip = ? OR username = ?", target, target, target).First(&guest).Error; err != nil { return err }
	if guest.IsOnline { ac, _ := s.getACConfig(guest.APMAC); radius.SendDisconnect(ac.ACIP, ac.ACSecret, guest.Username, guest.UserMAC, guest.UserIP); s.kickViaPortalSpecial(ac.ACIP, guest.UserIP) }
	s.DB.Unscoped().Delete(&guest)
	s.logAudit(guest.Username, guest.RealName, guest.UserIP, guest.UserMAC, guest.APMAC, "", "KICK", "SUCCESS", "Admin Manual Kick")
	return nil
}
func (s *AuthService) LoginCheck(username, password, realName, userIP, userMAC, apMac string) (string, *models.APACMap, error) {
	ac, err := s.getACConfig(apMac); if err != nil { return "", nil, fmt.Errorf("未知 AP: %s", apMac) }
	q := s.DB.Unscoped().Where("user_ip = ?", userIP); if userMAC != "" { q = q.Or("user_mac = ?", userMAC) }; q.Delete(&models.Guest{})
	var count int64; s.DB.Model(&models.Guest{}).Where("username = ? AND expires_at > ?", username, time.Now()).Count(&count)
	if count >= 3 { return "", &ac, fmt.Errorf("设备超限(当前%d/限制3)", count) }
	newGuest := models.Guest{ Username: username, RealName: realName, UserIP: userIP, UserMAC: userMAC, APMAC: apMac, SessionID: fmt.Sprintf("HTTP-%d", time.Now().Unix()), LoginTime: time.Now(), IsOnline: true, ExpiresAt: time.Now().Add(s.GetValidityDuration()) }
	if err := s.DB.Create(&newGuest).Error; err != nil { return "", &ac, err }
	if ac.PortalVer == 2 { if err := portal.SendLoginV2(userIP, username, password, ac.ACIP, ac.ACPort, ac.ACSecret); err != nil { s.logAudit(username, realName, userIP, userMAC, apMac, ac.ACIP, "LOGIN", "FAILED", err.Error()); s.DB.Unscoped().Delete(&newGuest); return "", &ac, err } }
	s.logAudit(username, realName, userIP, userMAC, apMac, ac.ACIP, "LOGIN", "SUCCESS", fmt.Sprintf("Device %d/3", count+1))
	return s.GetConfig("redirect_url"), &ac, nil
}
func (s *AuthService) kickViaPortalSpecial(acIP string, userIP string) error {
	if userIP == "" || userIP == "0.0.0.0" { return nil }
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s:8000/login", acIP), strings.NewReader(url.Values{ "cmd": {"disconnect"}, "ip-address": {userIP} }.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req); if err == nil { defer resp.Body.Close() }; return err
}
func cleanMAC(mac string) string { return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""), ".", "")) }
func (s *AuthService) GetValidityDuration() time.Duration { val := s.GetConfig("auth_validity_hours"); h, _ := strconv.Atoi(val); if h <= 0 { h = 24 }; return time.Duration(h) * time.Hour }
func (s *AuthService) getACConfig(apMac string) (models.APACMap, error) { var c models.APACMap; s.DB.Raw("SELECT * FROM apac_maps WHERE LOWER(REPLACE(REPLACE(REPLACE(apmac, ':', ''), '-', ''), '.', '')) = ? LIMIT 1", cleanMAC(apMac)).Scan(&c); if c.ID > 0 { return c, nil }; return models.APACMap{ACIP: "172.16.36.254", ACPort: 8000, ACSecret: "Huawei"}, nil }
func (s *AuthService) AddToTrustList(u, r, i, m, a string) (*models.APACMap, error) { _, ac, err := s.LoginCheck(u, "", r, i, m, a); return ac, err }
func (s *AuthService) GetConfig(key string) string { var c models.SystemConfig; if s.DB.Where(&models.SystemConfig{Key: key}).First(&c).Error != nil { if key == "redirect_url" { return "http://www.baidu.com" }; if key == "auth_validity_hours" { return "24" }; return "" }; return c.Value }
func (s *AuthService) SaveConfig(key, value string) error { return s.DB.Save(&models.SystemConfig{Key: key, Value: value}).Error }
func (s *AuthService) GetDashboardStats() map[string]int64 { var o, a, t int64; s.DB.Model(&models.Guest{}).Where("is_online = ?", true).Count(&o); s.DB.Model(&models.APACMap{}).Count(&a); s.DB.Model(&models.AuditLog{}).Where("action=? AND result=? AND created_at>=?", "LOGIN", "SUCCESS", time.Now().Format("2006-01-02")).Count(&t); return map[string]int64{"online":o,"ap_count":a,"today_auth":t} }
func (s *AuthService) SaveAPAC(item *models.APACMap) error { if item.ID == 0 { item.CreatedAt = time.Now(); return s.DB.Create(item).Error }; return s.DB.Model(item).Omit("CreatedAt").Save(item).Error }
func (s *AuthService) SendCode(phone string) error { return nil }
func (s *AuthService) verifyCode(phone, code string) error { return nil }
func (s *AuthService) GetOnlineUsers() ([]models.Guest, error) { var u []models.Guest; s.DB.Order("is_online desc, created_at desc").Find(&u); return u, nil }
func (s *AuthService) GetAuditLogs() ([]models.AuditLog, error) { var l []models.AuditLog; s.DB.Limit(50).Order("created_at desc").Find(&l); return l, nil }
func (s *AuthService) GetAPACList() ([]models.APACMap, error) { var l []models.APACMap; s.DB.Find(&l); return l, nil }
func (s *AuthService) DeleteAPAC(id uint) error { return s.DB.Delete(&models.APACMap{}, id).Error }
func (s *AuthService) GetACConfigByIP(userIP string) (models.APACMap, error) { return s.getACConfig("") }
func (s *AuthService) logAudit(user, realName, ip, mac, ap, ac, action, res, msg string) { s.DB.Create(&models.AuditLog{Username: user, RealName: realName, UserIP: ip, UserMAC: mac, APMAC: ap, ACIP: ac, Action: action, Result: res, Message: msg, CreatedAt: time.Now()}) }
