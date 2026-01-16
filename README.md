## Huawei Portal Authentication System (Go)

这是一个基于 Go 语言 (Gin + Gorm) 开发的华为 Portal 认证系统。它集成了 Portal V2 协议与 RADIUS 认证/计费功能，支持华为 AC 控制器的访客网络认证、无感认证以及后台管理。

## 📖 系统逻辑与架构

本系统主要由三个核心模块组成，协同工作以完成用户认证和网络授权：

1. Web 服务 (Portal Server)
交互流程：

用户连接 WiFi，AC 控制器拦截 HTTP 请求并将用户重定向到本系统的登录页面 (/)。

用户输入手机号/姓名并提交。

系统将用户信息写入数据库（标记为在线）。

核心动作：系统作为 Portal Client，通过 UDP 向 AC 发送 REQ_AUTH (Portal V2 协议) 报文，通知 AC 放行该用户 IP。

前端轮询状态，检测到放行成功后跳转至目标网页。

2. RADIUS 服务 (Auth & Accounting)
系统内置了 RADIUS Server (监听 1812/1813 端口)，用于维持用户状态：

认证 (1812)：处理 MAC 优先认证（无感认证）。如果用户在数据库中且未过期，RADIUS 直接返回 Access-Accept，用户无需再次输入手机号。

计费 (1813)：

Accounting-Start：AC 通知系统用户已上线，系统更新数据库状态。

Accounting-Stop：用户断开 WiFi 或超时，AC 通知系统，系统将用户标记为离线并记录审计日志。

Interim-Update：定期更新用户在线时间。

3. 管理后台 (Admin Dashboard)
提供可视化界面管理在线用户、查看审计日志。

支持配置 AC/AP 映射关系（不同 AP 下的用户可由不同的 AC 处理）。

强制下线：支持通过 Portal 协议或 RADIUS DM (Disconnect Message) 强制踢用户下线。

## 🛠️ 技术栈
语言: Golang 1.20+

Web 框架: Gin

ORM 框架: Gorm (MySQL)

协议库: Layeh RADIUS, Native UDP (Portal V2)

前端: HTML/CSS/JS (原生), 模版渲染

## 🚀 部署指南
1. 环境准备
MySQL 5.7 或 8.0

Golang 环境 (编译用)

服务器需开放端口：

8080 (TCP): Web 管理与 Portal 页面

1812 (UDP): RADIUS 认证

1813 (UDP): RADIUS 计费

50100 (UDP): Portal 协议交互

2. 配置文件修改
⚠️ 注意：由于代码中包含硬编码的数据库连接串，部署前请务必修改。

打开 cmd/server/main.go 和 cmd/tools/migrate.go，找到如下行并修改为你自己的数据库配置：

Go

// 修改为你的 MySQL 账号、密码、IP 和数据库名
dsn := "root:你的密码@tcp(127.0.0.1:3306)/guest_database?charset=utf8mb4&parseTime=True&loc=Local"
同时，在 cmd/server/main.go 中，你可以修改 RADIUS 的密钥（Secret）：

Go

// 默认为 qsq915open，需与 AC配置一致
go radius.StartRadiusServer(db, "你的RADIUS密钥") 
go radius.StartAcctServer(db, "你的RADIUS密钥")
3. 数据库初始化
首次部署需要创建数据库并迁移表结构。

在 MySQL 中创建数据库：

SQL

CREATE DATABASE guest_database DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
运行迁移工具：

Bash

go run cmd/tools/migrate.go
如果输出 Migration Complete 则表示表结构创建成功。

4. 编译与运行
编译项目：

Bash

go mod tidy
go build -o portal-server cmd/server/main.go
启动服务： Linux 环境下建议使用 nohup 或 systemd 运行：

Bash

chmod +x portal-server
./portal-server
启动成功后，控制台会显示：

RADIUS Auth Server listening on :1812...

RADIUS Acct Server listening on :1813...

Server starting on :8080...

## ⚙️ 华为 AC 关键配置参考
为了让系统正常工作，你需要在华为 AC (Access Controller) 上进行对应的配置。

RADIUS 服务器模版

Plaintext

radius-server template guest_radius
 radius-server shared-key cipher <你的RADIUS密钥>
 radius-server authentication <你的服务器IP> 1812 weight 80
 radius-server accounting <你的服务器IP> 1813 weight 80
Portal 服务器模版

Plaintext

web-auth-server guest_portal
 server-ip <你的服务器IP>
 port 50100
 url http://<你的服务器IP>:8080/
 protocol portal
 source-ip <AC的接口IP>
认证方案与域

配置 AAA 方案引用 RADIUS 模版。

配置 Domain 引用 AAA 方案。

在 VAP 模版或接口下绑定 Portal 模版 (Portal V2)。

## 🖥️ 管理后台使用
后台地址: http://<服务器IP>:8080/login-admin

默认账号: admin

默认密码: password123 (首次启动自动创建，请登录后立即修改)

主要功能：

AP/AC 配置：必须在此处添加 AC 的 IP 和 Shared Secret，否则 Portal 认证报文无法发送。

Secret: 必须与 AC 上配置的 Portal 密钥一致（注意区分 RADIUS 密钥和 Portal 密钥）。

手动添加用户：即白名单功能，添加后用户可通过 RADIUS 无感认证直接上网。

在线用户管理：可查看当前在线人员，并执行强制下线操作。

## 📂 目录结构说明

├── cmd

│   ├── server          # 主程序入口

│   │   └── main.go

│   └── tools           # 数据库迁移工具

│       └── migrate.go

├── internal

│   ├── models          # Gorm 数据库模型

│   ├── portal          # Portal V2 协议封装 (UDP发包/解包)

│   ├── radius          # RADIUS 服务逻辑 (Auth/Acct)

│   └── service         # 核心业务逻辑 (登录检查、踢人、配置读取)

├── templates           # HTML 前端模版

└── go.mod              # 依赖定义

## ⚠️ 注意事项
防火墙: 确保服务器防火墙放行了 UDP 50100 端口，否则 AC 发送的 Challenge 请求无法到达服务器，会导致认证超时。

时区: 确保服务器与 AC 时间同步，Portal 协议对时间戳或 Serial No 有一定验证机制。

MAC 地址格式: 系统内部统一处理为小写无分隔符格式（如 aabbccddeeff），但在界面显示时可能保留原样。
