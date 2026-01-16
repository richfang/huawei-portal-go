package main

import (
	"fmt"
	"huawei-portal-go/internal/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	dsn := "root:Qsq915open.@tcp(172.16.24.8:3306)/guest_database?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil { panic(err) }

	fmt.Println(">>> Migrating APACMap for Protocol Version...")
	err = db.AutoMigrate(&models.APACMap{})
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
	} else {
		fmt.Println("✅ Success! APACMap now has 'portal_ver' column.")
	}
}
