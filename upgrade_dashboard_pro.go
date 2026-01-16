package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const ProjectName = "."

var files = map[string]string{
	// 1. [Service] 升级统计逻辑：支持成功/失败对比，支持失败原因分析
	"internal/service/auth_service.go": `package service

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

// 1. 获取认证趋势 (双轨：总数 vs 成功数)
func (s *AuthService) Get24HourTrend() (map[string]interface{}, error) {
	type Result struct {
		HourStr string
		Total   int
		Success int
	}
	var results []Result
	
	// 使用 SUM(CASE...) 一次性查出总量和成功量
	sql := "SELECT DATE_FORMAT(created_at, '%H:00') as hour_str, " +
	       "COUNT(*) as total, " +
	       "SUM(CASE WHEN result='SUCCESS' THEN 1 ELSE 0 END) as success " +
	       "FROM audit_logs " +
	       "WHERE action='LOGIN' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) " +
	       "GROUP BY hour_str " +
	       "ORDER BY MIN(created_at)"
	
	if err := s.DB.Raw(sql).Scan(&results).Error; err != nil { return nil, err }

	hours := []string{}
	totalData := []int{}
	successData := []int{}
	
	for _, r := range results {
		hours = append(hours, r.HourStr)
		totalData = append(totalData, r.Total)
		successData = append(successData, r.Success)
	}
	return map[string]interface{}{"hours": hours, "total": totalData, "success": successData}, nil
}

// 2. 获取失败原因分布 (饼图)
func (s *AuthService) GetFailureAnalysis() ([]map[string]interface{}, error) {
	type Result struct {
		Message string
		Count   int
	}
	var results []Result
	
	// 统计最近 24 小时的失败原因
	sql := "SELECT message, COUNT(*) as count FROM audit_logs " +
	       "WHERE action='LOGIN' AND result!='SUCCESS' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) " +
	       "GROUP BY message ORDER BY count DESC LIMIT 5"
	
	if err := s.DB.Raw(sql).Scan(&results).Error; err != nil { return nil, err }

	data := []map[string]interface{}{}
	for _, r := range results {
		// 简化错误信息显示
		msg := r.Message
		if strings.Contains(msg, "password") { msg = "密码错误" }
		if strings.Contains(msg, "limit") || strings.Contains(msg, "超限") { msg = "设备超限" }
		if strings.Contains(msg, "exist") { msg = "用户已存在" }
		
		data = append(data, map[string]interface{}{"name": msg, "value": r.Count})
	}
	// 如果没有失败记录，返回空数据以免前端报错
	if len(data) == 0 {
		data = append(data, map[string]interface{}{"name": "无异常", "value": 0})
	}
	return data, nil
}

// 3. 获取 Top AP (保持不变)
func (s *AuthService) GetTopAPs() (map[string]interface{}, error) {
	type Result struct { APMAC string; Count int }
	var results []Result
	sql := "SELECT apmac, COUNT(*) as count FROM guests WHERE is_online=true GROUP BY apmac ORDER BY count DESC LIMIT 5"
	if err := s.DB.Raw(sql).Scan(&results).Error; err != nil { return nil, err }
	aps := []string{}; counts := []int{}
	for _, r := range results {
		n := r.APMAC; if n == "" { n = "未知AP" }
		aps = append(aps, n); counts = append(counts, r.Count)
	}
	return map[string]interface{}{"aps": aps, "counts": counts}, nil
}

// ---------------- 核心业务逻辑 (保持不变) ----------------

func (s *AuthService) VerifyAdminPassword(username, password string) bool {
	var admin models.Admin
	if err := s.DB.Where("username = ?", username).First(&admin).Error; err != nil { return false }
	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password)) == nil { return true }
	if admin.Password == password {
		h, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		s.DB.Model(&admin).Update("password", string(h))
		return true
	}
	return false
}
func (s *AuthService) UpdatePassword(username, oldPwd, newPwd string) error {
	if !s.VerifyAdminPassword(username, oldPwd) { return errors.New("原密码错误") }
	h, err := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	if err != nil { return err }
	return s.DB.Model(&models.Admin{}).Where("username = ?", username).Update("password", string(h)).Error
}
func (s *AuthService) StartCleaner() {
	go func() { for range time.Tick(1 * time.Minute) { s.cleanExpiredUsers() } }()
}
func (s *AuthService) cleanExpiredUsers() {
	var expired []models.Guest
	s.DB.Where("is_online = ? AND expires_at < ?", true, time.Now()).Find(&expired)
	for _, u := range expired {
		if u.APMAC != "" {
			ac, _ := s.getACConfig(u.APMAC)
			go radius.SendDisconnect(ac.ACIP, ac.ACSecret, u.Username, u.UserMAC, u.UserIP)
		}
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
	if guest.IsOnline {
		ac, _ := s.getACConfig(guest.APMAC)
		radius.SendDisconnect(ac.ACIP, ac.ACSecret, guest.Username, guest.UserMAC, guest.UserIP)
		s.kickViaPortalSpecial(ac.ACIP, guest.UserIP)
	}
	s.DB.Unscoped().Delete(&guest)
	s.logAudit(guest.Username, guest.RealName, guest.UserIP, guest.UserMAC, guest.APMAC, "", "KICK", "SUCCESS", "Admin Manual Kick")
	return nil
}
func (s *AuthService) LoginCheck(username, password, realName, userIP, userMAC, apMac string) (string, *models.APACMap, error) {
	ac, err := s.getACConfig(apMac)
	if err != nil { return "", nil, fmt.Errorf("未知 AP: %s", apMac) }
	q := s.DB.Unscoped().Where("user_ip = ?", userIP)
	if userMAC != "" { q = q.Or("user_mac = ?", userMAC) }
	q.Delete(&models.Guest{})
	var count int64
	s.DB.Model(&models.Guest{}).Where("username = ? AND expires_at > ?", username, time.Now()).Count(&count)
	if count >= 3 { return "", &ac, fmt.Errorf("设备超限(当前%d/限制3)", count) }
	newGuest := models.Guest{ Username: username, RealName: realName, UserIP: userIP, UserMAC: userMAC, APMAC: apMac, SessionID: fmt.Sprintf("HTTP-%d", time.Now().Unix()), LoginTime: time.Now(), IsOnline: true, ExpiresAt: time.Now().Add(s.GetValidityDuration()) }
	if err := s.DB.Create(&newGuest).Error; err != nil { return "", &ac, err }
	if ac.PortalVer == 2 {
		if err := portal.SendLoginV2(userIP, username, password, ac.ACIP, ac.ACPort, ac.ACSecret); err != nil {
			s.logAudit(username, realName, userIP, userMAC, apMac, ac.ACIP, "LOGIN", "FAILED", err.Error())
			s.DB.Unscoped().Delete(&newGuest)
			return "", &ac, err
		}
	}
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
func (s *AuthService) ManualAddUser(username, realName, mac string, hours int) error {
	var dup int64; q := s.DB.Model(&models.Guest{}).Where("username = ?", username)
	if mac != "" { q = q.Where("user_mac = ?", mac) } else { q = q.Where("user_mac = '' OR user_mac IS NULL") }
	q.Count(&dup); if dup > 0 { return errors.New("该设备已存在") }
	var count int64; s.DB.Model(&models.Guest{}).Where("username = ? AND expires_at > ?", username, time.Now()).Count(&count)
	if count >= 3 { return fmt.Errorf("账号限额已满(3条)") }
	if hours <= 0 { hours = 24 }
	return s.DB.Create(&models.Guest{ Username: username, RealName: realName, UserMAC: mac, LoginTime: time.Now(), IsOnline: false, SessionID: "MANUAL", ExpiresAt: time.Now().Add(time.Duration(hours) * time.Hour) }).Error
}
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
`,

	// 2. [Main] 注册新的失败原因分析路由
	"cmd/server/main.go": `package main

import (
	"fmt"
	"huawei-portal-go/internal/models"
	"huawei-portal-go/internal/radius"
	"huawei-portal-go/internal/service"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func AdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		adminUser := session.Get("admin_user")
		if adminUser == nil {
			if c.GetHeader("X-Requested-With") == "XMLHttpRequest" { c.AbortWithStatusJSON(401, gin.H{"success": false, "message": "会话已过期"}) } else { c.Redirect(http.StatusFound, "/login-admin"); c.Abort() }
			return
		}
		c.Next()
	}
}

func main() {
	dsn := "root:Qsq915open.@tcp(172.16.24.8:3306)/guest_database?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil { panic(err) }
	
	db.AutoMigrate(&models.Guest{}, &models.AuditLog{}, &models.APACMap{}, &models.VerificationCode{}, &models.Admin{}, &models.SystemConfig{})

	var count int64
	db.Model(&models.SystemConfig{}).Where(&models.SystemConfig{Key: "redirect_url"}).Count(&count)
	if count == 0 { db.Create(&models.SystemConfig{Key: "redirect_url", Value: "http://www.baidu.com"}) }
	db.Model(&models.Admin{}).Count(&count)
	if count == 0 { db.Create(&models.Admin{Username: "admin", Password: "password123"}) }

	go radius.StartRadiusServer(db, "qsq915open") 
	go radius.StartAcctServer(db, "qsq915open")

	authService := service.NewAuthService(db)
	authService.StartCleaner()

	r := gin.Default()
	store := cookie.NewStore([]byte("KN-PORTAL-SECRET-KEY-2026"))
	store.Options(sessions.Options{Path:"/", MaxAge:86400, HttpOnly:true})
	r.Use(sessions.Sessions("mysession", store))

	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		userIP := c.Query("wlanuserip"); if userIP == "" { userIP = c.Query("userip") }; if userIP == "" { userIP = c.ClientIP() }
		redirectURL := c.Query("url"); if redirectURL == "" { redirectURL = c.Query("redirect-url") }; if redirectURL == "" { redirectURL = c.Query("wlanoriginalurl") }; if redirectURL == "" { redirectURL = "http://www.baidu.com" }
		userMac := c.Query("wlanusermac"); if userMac == "" { userMac = c.Query("usermac") }
		if onlineUser, err := authService.CheckOnline(userIP, userMac); err == nil {
			ac, _ := authService.GetACConfigByIP(userIP)
			c.HTML(http.StatusOK, "success.html", gin.H{"UserIP": userIP, "Username": onlineUser.Username, "ACIP": ac.ACIP, "ACPort": ac.ACPort})
			return
		}
		c.HTML(http.StatusOK, "login.html", gin.H{"UserIP": userIP, "UserMAC": userMac, "APMAC": c.Query("apmac"), "RedirectURL": redirectURL, "SSID": c.Query("ssid"), "WlanACName": c.Query("wlanacname")})
	})

	r.POST("/portal/auth", func(c *gin.Context) {
		var req struct { Username, Password, RealName, UserIP, UserMAC, APMAC string }
		c.ShouldBindJSON(&req); if req.UserIP == "" { req.UserIP = c.ClientIP() }
		redirectURL, acConfig, err := authService.LoginCheck(req.Username, req.Password, req.RealName, req.UserIP, req.UserMAC, req.APMAC)
		if err != nil { c.JSON(500, gin.H{"success": false, "message": err.Error()}) } else { c.JSON(200, gin.H{"success": true, "ac_ip": acConfig.ACIP, "ac_port": acConfig.ACPort, "login_path": "/login", "redirect_url": redirectURL}) }
	})
	
	r.GET("/portal/status", func(c *gin.Context) {
		userIP := c.Query("ip"); if userIP == "" { userIP = c.ClientIP() }
		if _, err := authService.CheckOnline(userIP, c.Query("mac")); err == nil { c.JSON(200, gin.H{"online": true, "redirect_url": authService.GetConfig("redirect_url")}) } else { c.JSON(200, gin.H{"online": false}) }
	})

	r.GET("/login-admin", func(c *gin.Context) { c.HTML(http.StatusOK, "admin_login.html", nil) })
	r.POST("/api/admin/login", func(c *gin.Context) {
		var req struct { Username, Password string }; c.ShouldBindJSON(&req)
		if authService.VerifyAdminPassword(req.Username, req.Password) {
			s := sessions.Default(c); s.Set("admin_user", req.Username); s.Save(); c.JSON(200, gin.H{"success": true})
		} else { c.JSON(200, gin.H{"success": false, "message": "账号或密码错误"}) }
	})
	r.GET("/admin/logout", func(c *gin.Context) { s := sessions.Default(c); s.Clear(); s.Save(); c.Redirect(http.StatusFound, "/login-admin") })

	admin := r.Group("/admin"); admin.Use(AdminAuth())
	{
		admin.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "admin_dashboard.html", nil) })
		admin.GET("/stats", func(c *gin.Context) { c.JSON(200, authService.GetDashboardStats()) })
		admin.GET("/chart/trend", func(c *gin.Context) { data, _ := authService.Get24HourTrend(); c.JSON(200, data) })
		
		// 【新增】注册失败原因分析接口
		admin.GET("/chart/failure", func(c *gin.Context) { data, _ := authService.GetFailureAnalysis(); c.JSON(200, data) })
		
		admin.GET("/chart/top_ap", func(c *gin.Context) { data, _ := authService.GetTopAPs(); c.JSON(200, data) })
		admin.GET("/config", func(c *gin.Context) { c.JSON(200, gin.H{"value": authService.GetConfig(c.Query("key"))}) })
		admin.POST("/config", func(c *gin.Context) { var req struct{ Key, Value string }; c.ShouldBindJSON(&req); authService.SaveConfig(req.Key, req.Value); c.JSON(200, gin.H{"success": true}) })
		admin.POST("/kick", func(c *gin.Context) { t:=c.Query("target"); if t==""{t=c.Query("user_ip")}; authService.ManualLogout(t); c.JSON(200, gin.H{"success": true}) })
		admin.GET("/online", func(c *gin.Context) { users, _ := authService.GetOnlineUsers(); c.JSON(200, users) })
		admin.POST("/guest", func(c *gin.Context) { var req struct { Username, RealName, UserMAC string; Hours int }; c.ShouldBindJSON(&req); if err := authService.ManualAddUser(req.Username, req.RealName, req.UserMAC, req.Hours); err != nil { c.JSON(200, gin.H{"success": false, "message": err.Error()}) } else { c.JSON(200, gin.H{"success": true}) } })
		admin.GET("/audit", func(c *gin.Context) { logs, _ := authService.GetAuditLogs(); c.JSON(200, logs) })
		admin.GET("/apac", func(c *gin.Context) { list, _ := authService.GetAPACList(); c.JSON(200, list) })
		admin.POST("/apac", func(c *gin.Context) { var i models.APACMap; c.ShouldBindJSON(&i); authService.SaveAPAC(&i); c.JSON(200, gin.H{"success": true}) })
		admin.DELETE("/apac/:id", func(c *gin.Context) { id, _ := strconv.Atoi(c.Param("id")); authService.DeleteAPAC(uint(id)); c.JSON(200, gin.H{"success": true}) })
		admin.POST("/password", func(c *gin.Context) { var req struct{ OldPassword, NewPassword string }; c.ShouldBindJSON(&req); s := sessions.Default(c); u := s.Get("admin_user").(string); if err := authService.UpdatePassword(u, req.OldPassword, req.NewPassword); err != nil { c.JSON(200, gin.H{"success": false, "message": err.Error()}) } else { c.JSON(200, gin.H{"success": true}) } })
	}
	fmt.Println("Server starting on :8080...")
	r.Run(":8080")
}
`,

	// 3. [Frontend] Pro 版仪表盘 (增加失败原因分析图，优化 ECharts 样式)
	"templates/admin_dashboard.html": `<!DOCTYPE html>
<html>
<head>
    <title>Portal 统一管理平台</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        :root { --primary: #1677ff; --bg: #f0f2f5; --white: #ffffff; --text: #333; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; display: flex; height: 100vh; background: var(--bg); color: var(--text); }
        .sidebar { width: 240px; background: #001529; color: rgba(255,255,255,0.65); display: flex; flex-direction: column; }
        .logo { height: 64px; line-height: 64px; padding-left: 24px; font-size: 20px; font-weight: 700; color: #fff; background: #002140; }
        .menu-item { padding: 16px 24px; cursor: pointer; transition: 0.3s; font-size: 14px; }
        .menu-item.active { background: var(--primary); color: #fff; }
        .logout { margin-top: auto; padding: 16px 24px; background: #002140; cursor: pointer; color: #ff4d4f; }
        .main { flex: 1; padding: 24px; overflow-y: auto; display: flex; flex-direction: column; gap: 24px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        h2 { margin: 0; font-size: 24px; font-weight: 600; }
        .card { background: var(--white); border-radius: 8px; padding: 24px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }
        .stat-card { display: flex; align-items: center; padding: 24px; border-radius: 12px; }
        .stat-card.blue { background: linear-gradient(135deg, #e6f4ff 0%, #bae0ff 100%); }
        .stat-card.green { background: linear-gradient(135deg, #f6ffed 0%, #d9f7be 100%); }
        .stat-card.purple { background: linear-gradient(135deg, #f9f0ff 0%, #efdbff 100%); }
        .stat-icon { font-size: 24px; margin-right: 16px; }
        .stat-info div:last-child { font-size: 28px; font-weight: 700; color: #1f1f1f; }
        
        /* 布局调整：上方两个图，下方一个通栏图 */
        .charts-row-top { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; height: 380px; }
        .charts-row-btm { height: 320px; }
        .chart-box { height: 100%; display: flex; flex-direction: column; }
        .chart-title { font-size: 16px; font-weight: 600; margin-bottom: 15px; border-left: 4px solid var(--primary); padding-left: 10px; }
        
        #chart-trend, #chart-fail, #chart-ap { flex: 1; width: 100%; }
        
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th { background: #fafafa; padding: 16px; text-align: left; border-bottom: 1px solid #f0f0f0; }
        td { padding: 16px; border-bottom: 1px solid #f0f0f0; }
        button { cursor: pointer; border: none; padding: 6px 12px; border-radius: 4px; font-size: 13px; margin-right: 5px; }
        .btn-primary { background: var(--primary); color: #fff; }
        .btn-danger { background: #ff4d4f; color: #fff; }
        .btn-default { background: #fff; border: 1px solid #d9d9d9; }
        .btn-warn { background: #faad14; color: #fff; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .online { background: #52c41a; }
        .expired { background: #ff4d4f; }
        .offline { background: #d9d9d9; }
        .tag { padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .tag-http { background: #e6f4ff; color: #1677ff; border: 1px solid #91caff; }
        .tag-udp { background: #f6ffed; color: #52c41a; border: 1px solid #b7eb8f; }
        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.45); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal { background: #fff; width: 480px; padding: 24px; border-radius: 8px; box-shadow: 0 6px 16px rgba(0,0,0,0.12); }
        .form-row { margin-bottom: 16px; }
        .form-row label { display: block; margin-bottom: 6px; font-size: 14px; color: #666; }
        .form-row input, .form-row select { width: 100%; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 4px; box-sizing: border-box; }
        .section { display: none; }
        .section.active { display: block; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="logo">PORTAL ADMIN</div>
        <div class="menu-item active" onclick="switchTab('dashboard')">📊 仪表盘</div>
        <div class="menu-item" onclick="switchTab('online')">👥 用户管理</div>
        <div class="menu-item" onclick="switchTab('audit')">📝 审计日志</div>
        <div class="menu-item" onclick="switchTab('apac')">⚙️ 设备配置</div>
        <div class="menu-item" onclick="switchTab('config')">🛠️ 系统参数</div>
        <div class="menu-item" onclick="switchTab('security')">🔒 安全中心</div>
        <a href="/admin/logout" style="text-decoration:none;"><div class="logout">🚪 退出登录</div></a>
    </div>

    <div class="main">
        <div id="section-dashboard" class="section active">
            <div class="header"><h2>系统概览</h2><button class="btn-default" onclick="initDashboard()">🔄 刷新</button></div>
            <div class="stats-grid">
                <div class="stat-card blue"><div class="stat-icon">👥</div><div class="stat-info"><div>当前在线</div><div id="stat-online">0</div></div></div>
                <div class="stat-card green"><div class="stat-icon">📡</div><div class="stat-info"><div>接入 AP</div><div id="stat-ap">0</div></div></div>
                <div class="stat-card purple"><div class="stat-icon">✅</div><div class="stat-info"><div>今日认证</div><div id="stat-auth">0</div></div></div>
            </div>
            
            <div class="charts-row-top" style="margin-top:24px;">
                <div class="card chart-box">
                    <div class="chart-title">24小时认证流量趋势 (双轨)</div>
                    <div id="chart-trend"></div>
                </div>
                <div class="card chart-box">
                    <div class="chart-title">认证失败原因 Top 5</div>
                    <div id="chart-fail"></div>
                </div>
            </div>
            
            <div class="card chart-box charts-row-btm" style="margin-top:24px;">
                <div class="chart-title">热门 AP 负载 Top 5</div>
                <div id="chart-ap"></div>
            </div>
        </div>

        <div id="section-online" class="section">
            <div class="header"><h2>用户管理</h2><div><button class="btn-primary" onclick="openUserModal()">+ 新增白名单</button> <button class="btn-default" onclick="loadOnline()">刷新</button></div></div>
            <div class="card"><table><thead><tr><th>用户</th><th>姓名</th><th>状态</th><th>IP</th><th>MAC</th><th>登录时间</th><th>到期时间</th><th>操作</th></tr></thead><tbody id="online-list"></tbody></table></div>
        </div>

        <div id="section-apac" class="section">
            <div class="header"><h2>设备配置</h2><div><button class="btn-primary" onclick="openModal()">+ 新增设备</button> <button class="btn-default" onclick="loadAPAC()">刷新</button></div></div>
            <div class="card"><table><thead><tr><th>AP MAC</th><th>AC IP</th><th>端口</th><th>协议</th><th>Secret</th><th>操作</th></tr></thead><tbody id="apac-list"></tbody></table></div>
        </div>

        <div id="section-audit" class="section"><div class="header"><h2>审计日志</h2><button class="btn-default" onclick="loadAudit()">刷新</button></div><div class="card"><table><thead><tr><th>时间</th><th>用户</th><th>IP</th><th>MAC</th><th>AP</th><th>动作</th><th>结果</th></tr></thead><tbody id="audit-list"></tbody></table></div></div>
        <div id="section-config" class="section"><div class="header"><h2>系统参数</h2></div><div class="card" style="max-width:500px"><div class="form-row"><label>认证成功跳转</label><input id="conf-redirect"></div><div class="form-row"><label>有效期(小时)</label><input id="conf-validity" type="number"></div><button class="btn-primary" onclick="saveConfig()">保存</button></div></div>
        <div id="section-security" class="section"><div class="header"><h2>修改密码</h2></div><div class="card" style="max-width:400px"><div class="form-row"><label>原密码</label><input type="password" id="pwd-old"></div><div class="form-row"><label>新密码</label><input type="password" id="pwd-new"></div><button class="btn-primary" onclick="changePassword()">修改</button></div></div>
    </div>

    <div class="modal-overlay" id="modal">
        <div class="modal">
            <h3 id="modal-title">配置 AP/AC</h3>
            <input type="hidden" id="edit-id">
            <div class="form-row"><label>AP MAC</label><input id="form-ap"></div>
            <div class="form-row"><label>AC IP</label><input id="form-ac"></div>
            <div class="form-row"><label>AC Port</label><input id="form-port" value="2000"></div>
            <div class="form-row"><label>协议</label><select id="form-ver"><option value="0">HTTP (默认)</option><option value="1">Portal V1</option><option value="2">Portal V2</option></select></div>
            <div class="form-row"><label>Secret</label><input id="form-secret" value="Huawei"></div>
            <div style="text-align:right"><button class="btn-default" onclick="closeModal()">取消</button> <button class="btn-primary" onclick="saveAPAC()">保存</button></div>
        </div>
    </div>

    <div class="modal-overlay" id="modal-user">
        <div class="modal">
            <h3>新增用户</h3>
            <div class="form-row"><label>账号</label><input id="u-name"></div>
            <div class="form-row"><label>姓名</label><input id="u-real"></div>
            <div class="form-row"><label>MAC (可选)</label><input id="u-mac"></div>
            <div class="form-row"><label>有效期 (小时)</label><input id="u-hours" type="number" value="720"></div>
            <div style="text-align:right"><button class="btn-default" onclick="closeUserModal()">取消</button> <button class="btn-primary" onclick="saveUser()">保存</button></div>
        </div>
    </div>

    <script>
        function switchTab(tab) {
            document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
            event.currentTarget.classList.add('active');
            document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
            document.getElementById('section-' + tab).classList.add('active');
            if(tab === 'dashboard') initDashboard(); else if(tab === 'online') loadOnline(); else if(tab === 'apac') loadAPAC(); else if(tab === 'audit') loadAudit(); else if(tab === 'config') loadConfig();
        }

        let trendChart, failChart, apChart;
        async function initDashboard() {
            try {
                const res = await fetch('/admin/stats'); const d = await res.json();
                document.getElementById('stat-online').innerText = d.online||0; document.getElementById('stat-ap').innerText = d.ap_count||0; document.getElementById('stat-auth').innerText = d.today_auth||0;
                
                if(!trendChart) trendChart = echarts.init(document.getElementById('chart-trend'));
                if(!failChart) failChart = echarts.init(document.getElementById('chart-fail'));
                if(!apChart) apChart = echarts.init(document.getElementById('chart-ap'));
                
                // 1. 趋势图 (双轨)
                const r1 = await fetch('/admin/chart/trend'); const d1 = await r1.json();
                trendChart.setOption({
                    tooltip:{trigger:'axis'}, legend:{data:['认证请求','成功认证']}, 
                    grid: {left:'3%', right:'4%', bottom:'3%', containLabel:true},
                    xAxis:{type:'category', boundaryGap:false, data:d1.hours||[]}, 
                    yAxis:{type:'value'}, 
                    series:[
                        {name:'认证请求', type:'line', smooth:true, data:d1.total||[], itemStyle:{color:'#999'}, lineStyle:{width:1, type:'dashed'}},
                        {name:'成功认证', type:'line', smooth:true, areaStyle:{opacity:0.2}, data:d1.success||[], itemStyle:{color:'#1677ff'}}
                    ]
                });
                
                // 2. 失败原因 (饼图)
                const rFail = await fetch('/admin/chart/failure'); const dFail = await rFail.json();
                failChart.setOption({
                    tooltip: {trigger:'item'},
                    series: [{
                        type: 'pie', radius: ['40%', '70%'], avoidLabelOverlap: false,
                        itemStyle: {borderRadius: 5, borderColor: '#fff', borderWidth: 2},
                        label: {show: false, position: 'center'},
                        emphasis: {label: {show: true, fontSize: 14, fontWeight: 'bold'}},
                        data: dFail || []
                    }]
                });

                // 3. 热门 AP
                const r2 = await fetch('/admin/chart/top_ap'); const d2 = await r2.json();
                apChart.setOption({tooltip:{trigger:'axis'}, xAxis:{type:'value'}, yAxis:{type:'category',data:d2.aps||[]}, series:[{type:'bar',data:d2.counts||[],itemStyle:{color:'#52c41a', borderRadius:[0,4,4,0]}}]});
                
                window.onresize = function() { trendChart.resize(); failChart.resize(); apChart.resize(); };
            } catch(e) {}
        }

        // --- 其他逻辑保持一致 ---
        async function loadOnline() {
            try {
                const res = await fetch('/admin/online'); const d = await res.json()||[]; const now = new Date();
                document.getElementById('online-list').innerHTML = d.map(u => {
                    let exp = new Date(u.ExpiresAt); let st = (u.IsOnline && exp > now) ? '<span class=\"status-dot online\"></span>在线' : '<span class=\"status-dot expired\"></span>过期';
                    return '<tr><td>'+u.Username+'</td><td>'+(u.RealName||'-')+'</td><td>'+st+'</td><td>'+(u.UserIP||'-')+'</td><td>'+(u.UserMAC||'-')+'</td><td>'+new Date(u.LoginTime).toLocaleString()+'</td><td>'+exp.toLocaleString()+'</td><td><button class=\"btn-warn\" onclick=\"kick(\''+(u.UserMAC||u.Username)+'\')\">下线</button></td></tr>';
                }).join('');
            } catch(e) {}
        }
        async function loadAPAC() {
            const res = await fetch('/admin/apac'); const d = await res.json()||[];
            document.getElementById('apac-list').innerHTML = d.map(i => {
                let tag = i.PortalVer==2 ? '<span class=\"tag tag-udp\">V2</span>' : (i.PortalVer==1 ? '<span class=\"tag tag-udp\">V1</span>' : '<span class=\"tag tag-http\">HTTP</span>');
                return '<tr><td>'+i.APMAC+'</td><td>'+i.ACIP+'</td><td>'+i.ACPort+'</td><td>'+tag+'</td><td>'+i.ACSecret+'</td><td><button class=\"btn-primary\" onclick=\'editAPAC('+JSON.stringify(i)+')\'>编辑</button> <button class=\"btn-danger\" onclick=\"delAPAC('+i.ID+')\">删除</button></td></tr>';
            }).join('');
        }
        async function loadAudit() { const r=await fetch('/admin/audit'); const d=await r.json(); document.getElementById('audit-list').innerHTML=d.map(l=>'<tr><td>'+new Date(l.CreatedAt).toLocaleString()+'</td><td>'+l.Username+'</td><td>'+l.UserIP+'</td><td>'+l.UserMAC+'</td><td>'+l.APMAC+'</td><td>'+l.Action+'</td><td>'+l.Result+'</td></tr>').join(''); }
        async function loadConfig() { const r1=await fetch('/admin/config?key=redirect_url');const d1=await r1.json();document.getElementById('conf-redirect').value=d1.value||''; const r2=await fetch('/admin/config?key=auth_validity_hours');const d2=await r2.json();document.getElementById('conf-validity').value=d2.value||24; }
        async function saveConfig() { await fetch('/admin/config',{method:'POST',body:JSON.stringify({key:'redirect_url',value:document.getElementById('conf-redirect').value})}); await fetch('/admin/config',{method:'POST',body:JSON.stringify({key:'auth_validity_hours',value:document.getElementById('conf-validity').value})}); alert('保存成功'); }
        function openModal() { document.getElementById('modal').style.display='flex'; document.getElementById('modal-title').innerText="新增配置"; document.getElementById('edit-id').value=''; document.getElementById('form-ap').value=''; document.getElementById('form-ac').value=''; document.getElementById('form-ver').value='0'; }
        function editAPAC(i) { openModal(); document.getElementById('modal-title').innerText="编辑配置"; document.getElementById('edit-id').value=i.ID; document.getElementById('form-ap').value=i.APMAC; document.getElementById('form-ac').value=i.ACIP; document.getElementById('form-port').value=i.ACPort; document.getElementById('form-secret').value=i.ACSecret; document.getElementById('form-ver').value=i.PortalVer; }
        function closeModal() { document.getElementById('modal').style.display='none'; }
        async function saveAPAC() { const b={ID:parseInt(document.getElementById('edit-id').value)||0, APMAC:document.getElementById('form-ap').value, ACIP:document.getElementById('form-ac').value, ACPort:parseInt(document.getElementById('form-port').value), ACSecret:document.getElementById('form-secret').value, PortalVer:parseInt(document.getElementById('form-ver').value)}; await fetch('/admin/apac',{method:'POST',body:JSON.stringify(b)}); closeModal(); loadAPAC(); }
        async function delAPAC(id) { if(confirm('删除?')) await fetch('/admin/apac/'+id,{method:'DELETE'}); loadAPAC(); }
        function openUserModal() { document.getElementById('modal-user').style.display='flex'; document.getElementById('u-name').value=''; }
        function closeUserModal() { document.getElementById('modal-user').style.display='none'; }
        async function saveUser() { const b={Username:document.getElementById('u-name').value, RealName:document.getElementById('u-real').value, UserMAC:document.getElementById('u-mac').value, Hours:parseInt(document.getElementById('u-hours').value)}; await fetch('/admin/guest',{method:'POST',body:JSON.stringify(b)}); closeUserModal(); loadOnline(); }
        async function kick(t) { if(confirm('下线?')) await fetch('/admin/kick?target='+t,{method:'POST'}); loadOnline(); }
        async function changePassword() { const o=document.getElementById('pwd-old').value, n=document.getElementById('pwd-new').value; const r=await fetch('/admin/password',{method:'POST',body:JSON.stringify({OldPassword:o,NewPassword:n})}); const d=await r.json(); alert(d.message||(d.success?'成功':'失败')); }
        
        initDashboard();
    </script>
</body>
</html>
`,
}

func main() {
	fmt.Printf("Upgrading Dashboard to PRO Version (Dual Trend + Failure Analysis)...%s\n", ProjectName)
	for path, content := range files {
		fullPath := filepath.Join(ProjectName, path)
		dir := filepath.Dir(fullPath)
		os.MkdirAll(dir, 0755)
		os.WriteFile(fullPath, []byte(content), 0644)
		fmt.Printf("Updated: %s\n", fullPath)
	}
	fmt.Println("Done! Please restart server: go run cmd/server/main.go")
}
