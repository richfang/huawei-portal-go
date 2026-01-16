package models

import (
	"time"
	"gorm.io/gorm"
)

type Guest struct {
	gorm.Model
	Username  string    `gorm:"type:varchar(191);index"`
	RealName  string    `gorm:"type:varchar(191)"`
	UserIP    string    `gorm:"type:varchar(50);index"`
	UserMAC   string    `gorm:"type:varchar(50);index"`
	APMAC     string    `gorm:"type:varchar(50)"`
	LoginTime time.Time
	SessionID string
	IsOnline  bool      `gorm:"default:false"`
	ExpiresAt time.Time
}

type AuditLog struct {
	ID        uint `gorm:"primarykey"`
	Username  string `gorm:"type:varchar(191)"`
	RealName  string `gorm:"type:varchar(191)"`
	UserIP    string `gorm:"type:varchar(50)"`
	UserMAC   string `gorm:"type:varchar(50)"`
	APMAC     string `gorm:"type:varchar(50)"`
	ACIP      string `gorm:"type:varchar(50)"`
	Action    string `gorm:"type:varchar(50)"`
	Result    string `gorm:"type:varchar(50)"`
	Message   string `gorm:"type:text"`
	CreatedAt time.Time
}

type APACMap struct {
	ID        uint `gorm:"primarykey"`
	APMAC     string `gorm:"type:varchar(50);index"`
	ACIP      string `gorm:"type:varchar(50)"`
	ACPort    int    // Portal 端口 (HTTP通常是2000/50100, UDP通常是2000)
	ACSecret  string
	// 【新增】协议版本: 0=HTTP(默认), 1=PortalV1, 2=PortalV2
	PortalVer int    `gorm:"default:0"` 
	CreatedAt time.Time
}

type VerificationCode struct {
	ID          uint `gorm:"primarykey"`
	PhoneNumber string `gorm:"type:varchar(20);index"`
	Code        string `gorm:"type:varchar(10)"`
	IsUsed      bool
	CreatedAt   time.Time
}

type Admin struct {
	ID       uint `gorm:"primarykey"`
	Username string `gorm:"type:varchar(191)"`
	Password string
}

type SystemConfig struct {
	Key   string `gorm:"primarykey;type:varchar(191)"`
	Value string
}
