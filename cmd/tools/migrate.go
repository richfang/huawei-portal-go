package main

import (
	"fmt"
	"huawei-portal-go/internal/models"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	dsn := "root:Qsq915open.@tcp(172.16.24.8:3306)/guest_database?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database: " + err.Error())
	}

	fmt.Println(">>> Starting Database Migration...")

	// 1. 强制迁移 Guest 表 (添加 is_online, expires_at)
	err = db.AutoMigrate(&models.Guest{})
	if err != nil {
		fmt.Printf("❌ Failed to migrate Guest: %v\n", err)
	} else {
		fmt.Println("✅ Guest table migrated successfully.")
	}

	// 2. 强制迁移 AuditLog 表 (添加 real_name)
	err = db.AutoMigrate(&models.AuditLog{})
	if err != nil {
		fmt.Printf("❌ Failed to migrate AuditLog: %v\n", err)
	} else {
		fmt.Println("✅ AuditLog table migrated successfully.")
	}

	// 3. 补充迁移其他表
	db.AutoMigrate(&models.APACMap{}, &models.VerificationCode{}, &models.Admin{}, &models.SystemConfig{})

	// 4. 修复旧数据 (可选：把 NULL 的 expires_at 填上未来时间，防止旧用户无法登录)
	// db.Model(&models.Guest{}).Where("expires_at IS NULL").Update("expires_at", time.Now().Add(24*time.Hour))
	
	fmt.Println(">>> Migration Complete! Please restart the server.")
}
