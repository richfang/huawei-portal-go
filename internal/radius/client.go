package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	CodeDisconnectRequest = 40
	CodeDisconnectACK     = 41
	CodeDisconnectNAK     = 42
)

// SendDisconnect 发送踢下线报文
// username: 认证时的用户名 (Portal用户是手机号, Mac认证用户是去符号MAC)
// userMAC:  用户的物理 MAC 地址 (带不带符号皆可，用于 Calling-Station-Id)
func SendDisconnect(acIP, secret, username, userMAC, userIP string) {
	addr := fmt.Sprintf("%s:3799", acIP)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Printf("[Kick] ❌ Connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	packetID := uint8(time.Now().Unix() % 255)
	buf := new(bytes.Buffer)
	
	buf.WriteByte(CodeDisconnectRequest)
	buf.WriteByte(packetID)
	binary.Write(buf, binary.BigEndian, uint16(0)) // Length占位
	authPos := buf.Len()
	buf.Write(make([]byte, 16)) // Authenticator占位

	// --- Attributes ---

	// 1. User-Name (Attr 1) - 核心匹配字段
	// 必须与 AC 上显示的在线用户名完全一致
	if len(username) > 0 {
		buf.WriteByte(1) 
		buf.WriteByte(uint8(2 + len(username)))
		buf.WriteString(username)
	}

	// 2. Framed-IP-Address (Attr 8)
	if userIP != "" && userIP != "0.0.0.0" {
		ip := net.ParseIP(userIP).To4()
		if ip != nil {
			buf.WriteByte(8)
			buf.WriteByte(6)
			buf.Write(ip)
		}
	}

	// 3. Calling-Station-Id (Attr 31) - 辅助匹配字段
	// 华为/H3C 通常需要此字段来定位终端
	if len(userMAC) > 0 {
		buf.WriteByte(31)
		buf.WriteByte(uint8(2 + len(userMAC)))
		buf.WriteString(userMAC)
	}

	// ------------------

	length := uint16(buf.Len())
	binary.BigEndian.PutUint16(buf.Bytes()[2:4], length)

	hash := md5.New()
	hash.Write(buf.Bytes())
	hash.Write([]byte(secret))
	sum := hash.Sum(nil)
	copy(buf.Bytes()[authPos:], sum)

	fmt.Printf("[Kick] 🚀 Sending DM to %s | User: %s | MAC: %s | IP: %s\n", addr, username, userMAC, userIP)
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		fmt.Printf("[Kick] ❌ Send failed: %v\n", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recvBuf := make([]byte, 1024)
	n, err := conn.Read(recvBuf)
	if err != nil {
		fmt.Printf("[Kick] ⚠️ No Response from AC (Timeout). Check AC 3799 port.\n")
		return
	}

	if n < 2 { return }
	respCode := recvBuf[0]
	
	if respCode == CodeDisconnectACK {
		fmt.Printf("[Kick] ✅ SUCCESS! AC confirmed disconnection.\n")
	} else if respCode == CodeDisconnectNAK {
		fmt.Printf("[Kick] ❌ FAILED! AC rejected the request (NAK).\n")
	}
}
