package main

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
			if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
				c.AbortWithStatusJSON(401, gin.H{"success": false, "message": "会话已过期"})
				return
			}
			c.Redirect(http.StatusFound, "/login-admin")
			c.Abort()
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
	db.Model(&models.SystemConfig{}).Where("`key` = ?", "redirect_url").Count(&count)
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
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			RealName string `json:"realname"`
			UserIP   string `json:"user_ip"`
			UserMAC  string `json:"user_mac"`
			APMAC    string `json:"ap_mac"`
		}
		c.ShouldBindJSON(&req)
		if req.UserIP == "" { req.UserIP = c.ClientIP() }
		redirectURL, acConfig, err := authService.LoginCheck(req.Username, req.Password, req.RealName, req.UserIP, req.UserMAC, req.APMAC)
		if err != nil { 
			c.JSON(500, gin.H{"success": false, "message": err.Error()})
			return 
		}
		// 【关键修复】增加了 proto_ver 字段，告诉前端当前 AC 的协议类型
		c.JSON(200, gin.H{
			"success": true, 
			"ac_ip": acConfig.ACIP, 
			"ac_port": acConfig.ACPort, 
			"login_path": "/login", 
			"redirect_url": redirectURL,
			"proto_ver": acConfig.PortalVer, // 0=HTTP, 1=V1, 2=V2
		})
	})
	
	r.GET("/portal/status", func(c *gin.Context) {
		userIP := c.Query("ip"); if userIP == "" { userIP = c.ClientIP() }
		userMac := c.Query("mac")
		if _, err := authService.CheckOnline(userIP, userMac); err == nil { 
			c.JSON(200, gin.H{"online": true, "redirect_url": authService.GetConfig("redirect_url")}) 
		} else { 
			c.JSON(200, gin.H{"online": false}) 
		}
	})

	r.GET("/login-admin", func(c *gin.Context) { c.HTML(http.StatusOK, "admin_login.html", nil) })

	r.POST("/api/admin/login", func(c *gin.Context) {
		var req struct { Username string; Password string }
		c.ShouldBindJSON(&req)
		if authService.VerifyAdminPassword(req.Username, req.Password) {
			session := sessions.Default(c)
			session.Set("admin_user", req.Username)
			session.Save()
			c.JSON(200, gin.H{"success": true})
		} else {
			c.JSON(200, gin.H{"success": false, "message": "账号或密码错误"})
		}
	})

	r.GET("/admin/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear(); session.Save()
		c.Redirect(http.StatusFound, "/login-admin")
	})

	admin := r.Group("/admin")
	admin.Use(AdminAuth())
	{
		admin.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "admin_dashboard.html", nil) })
		admin.GET("/stats", func(c *gin.Context) { c.JSON(200, authService.GetDashboardStats()) })
		admin.GET("/chart/trend", func(c *gin.Context) { data, _ := authService.Get24HourTrend(); c.JSON(200, data) })
		admin.GET("/chart/failure", func(c *gin.Context) { data, _ := authService.GetFailureAnalysis(); c.JSON(200, data) })
		admin.GET("/chart/top_ap", func(c *gin.Context) { data, _ := authService.GetTopAPs(); c.JSON(200, data) })
		admin.GET("/config", func(c *gin.Context) { c.JSON(200, gin.H{"value": authService.GetConfig(c.Query("key"))}) })
		admin.POST("/config", func(c *gin.Context) { var req struct{ Key, Value string }; c.ShouldBindJSON(&req); authService.SaveConfig(req.Key, req.Value); c.JSON(200, gin.H{"success": true}) })
		admin.POST("/kick", func(c *gin.Context) { 
			target := c.Query("target"); if target==""{target=c.Query("user_ip")}
			authService.ManualLogout(target); c.JSON(200, gin.H{"success": true}) 
		})
		admin.GET("/online", func(c *gin.Context) { users, _ := authService.GetOnlineUsers(); c.JSON(200, users) })
		admin.POST("/guest", func(c *gin.Context) {
			var req struct { Username, RealName, UserMAC string; Hours int }
			c.ShouldBindJSON(&req)
			if err := authService.ManualAddUser(req.Username, req.RealName, req.UserMAC, req.Hours); err != nil {
				c.JSON(200, gin.H{"success": false, "message": err.Error()})
			} else { c.JSON(200, gin.H{"success": true}) }
		})
		admin.GET("/audit", func(c *gin.Context) { logs, _ := authService.GetAuditLogs(); c.JSON(200, logs) })
		admin.GET("/apac", func(c *gin.Context) { list, _ := authService.GetAPACList(); c.JSON(200, list) })
		admin.POST("/apac", func(c *gin.Context) { var i models.APACMap; c.ShouldBindJSON(&i); authService.SaveAPAC(&i); c.JSON(200, gin.H{"success": true}) })
		admin.DELETE("/apac/:id", func(c *gin.Context) { id, _ := strconv.Atoi(c.Param("id")); authService.DeleteAPAC(uint(id)); c.JSON(200, gin.H{"success": true}) })
		admin.POST("/password", func(c *gin.Context) { 
			var req struct{ OldPassword, NewPassword string }; c.ShouldBindJSON(&req)
			session := sessions.Default(c); u := session.Get("admin_user").(string)
			if err := authService.UpdatePassword(u, req.OldPassword, req.NewPassword); err != nil { c.JSON(200, gin.H{"success": false, "message": err.Error()}) } else { c.JSON(200, gin.H{"success": true}) }
		})
	}
	fmt.Println("Server starting on :8080...")
	r.Run(":8080")
}
