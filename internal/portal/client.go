package portal

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	Ver2           = 0x02
	ReqChallenge   = 0x01
	AckChallenge   = 0x02
	ReqAuth        = 0x03
	AckAuth        = 0x04
	
	// 【修正】文档指出 CHAP 为 0
	MethodChap     = 0x00 
	MethodPap      = 0x01
)

// 计算 Authenticator: MD5( 报文内容 + Secret )
func calcAuthenticator(data []byte, secret string) []byte {
	m := md5.New()
	m.Write(data)
	m.Write([]byte(secret))
	return m.Sum(nil)
}

func SendLoginV2(userIP, username, password, acIP string, acPort int, secret string) error {
	localAddr, err := net.ResolveUDPAddr("udp", ":50100")
	if err != nil { return err }
	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", acIP, acPort))
	if err != nil { return err }

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil { return err }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// ==========================================
	// 1. 发送 REQ_CHALLENGE
	// ==========================================
	serialNo := uint16(time.Now().Unix() % 65535)
	// REQ_CHALLENGE 时 RequestID 通常为 0，由 AC 生成并返回
	reqID := uint16(0) 

	buf := new(bytes.Buffer)
	// --- Header (16 Bytes) ---
	binary.Write(buf, binary.BigEndian, uint8(Ver2))       
	binary.Write(buf, binary.BigEndian, uint8(ReqChallenge))
	binary.Write(buf, binary.BigEndian, uint8(MethodChap)) // 0x00
	binary.Write(buf, binary.BigEndian, uint8(0))          // Rsv
	binary.Write(buf, binary.BigEndian, serialNo)
	binary.Write(buf, binary.BigEndian, reqID)
	
	ip := net.ParseIP(userIP).To4()
	if ip == nil { return fmt.Errorf("无效 IP") }
	buf.Write(ip) // UserIP (4)
	
	binary.Write(buf, binary.BigEndian, uint16(0)) // Rsv (2) - UserPort
	binary.Write(buf, binary.BigEndian, uint8(0))  // ErrCode
	binary.Write(buf, binary.BigEndian, uint8(0))  // AttrNum

	// --- Authenticator (16 Bytes) ---
	// 先填 16 个 0 占位
	zeros := make([]byte, 16)
	buf.Write(zeros)

	// 计算签名: MD5( Header(含0验证字) + Secret )
	// 因为 REQ_CHALLENGE 没有属性，所以直接算
	auth := calcAuthenticator(buf.Bytes(), secret)
	
	// 把算出来的签名填回去 (覆盖最后 16 字节)
	copy(buf.Bytes()[16:], auth)

	fmt.Printf("[Portal-CHAP] 1. Sending REQ_CHALLENGE (Len=%d)...\n", buf.Len())
	if _, err := conn.Write(buf.Bytes()); err != nil { return err }

	// ==========================================
	// 2. 接收 ACK_CHALLENGE
	// ==========================================
	recv := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(recv)
	if err != nil { return fmt.Errorf("等待 Challenge 响应失败: %v", err) }
	
	// 校验响应
	if n < 32 { return fmt.Errorf("响应包太短: %d", n) }
	// 格式: Header(16) + Auth(16) + Attrs...
	
	respType := recv[1]
	respErr := recv[14] // ErrCode 是第 15 字节 (index 14)
	
	if respType != AckChallenge {
		return fmt.Errorf("收到错误的包类型: %d", respType)
	}
	if respErr != 0 {
		// 常见错误: 1=拒绝, 2=连接已建立
		return fmt.Errorf("AC 拒绝 Challenge 请求, ErrCode: %d", respErr)
	}

	// 获取关键信息
	reqID = binary.BigEndian.Uint16(recv[6:8]) // 获取 AC 生成的 RequestID
	fmt.Printf("[Portal-CHAP] 2. Got Challenge OK. ReqID=%d\n", reqID)

	// 解析属性寻找 Challenge (Type=0x03)
	// 属性从第 32 字节开始 (16头 + 16验证字)
	var challenge []byte
	offset := 32
	attrNum := int(recv[15])

	for i := 0; i < attrNum && offset < n; i++ {
		t := recv[offset]
		l := int(recv[offset+1])
		if l < 2 || offset+l > n { break }
		
		if t == 0x03 { // Challenge
			challenge = recv[offset+2 : offset+l]
		}
		offset += l
	}

	if len(challenge) == 0 { return fmt.Errorf("未找到 Challenge 属性") }

	// ==========================================
	// 3. 计算 CHAP Password
	// ==========================================
	// Huawei ChapPwd = MD5( RequestID + Password + Challenge )
	md5Pwd := md5.New()
	binary.Write(md5Pwd, binary.BigEndian, reqID)
	md5Pwd.Write([]byte(password))
	md5Pwd.Write(challenge)
	chapPwd := md5Pwd.Sum(nil)

	// ==========================================
	// 4. 发送 REQ_AUTH
	// ==========================================
	buf.Reset()
	// Header
	binary.Write(buf, binary.BigEndian, uint8(Ver2))
	binary.Write(buf, binary.BigEndian, uint8(ReqAuth))    // Type=3
	binary.Write(buf, binary.BigEndian, uint8(MethodChap)) // 0
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, serialNo)
	binary.Write(buf, binary.BigEndian, reqID)             // 使用 AC 返回的 ID
	buf.Write(ip)
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint8(2))          // AttrNum=2

	// Authenticator 占位
	buf.Write(zeros)

	// Attr 1: Username
	buf.WriteByte(0x01)
	buf.WriteByte(uint8(2 + len(username)))
	buf.WriteString(username)

	// Attr 2: ChapPassword
	buf.WriteByte(0x04)
	buf.WriteByte(uint8(2 + len(chapPwd)))
	buf.Write(chapPwd)

	// 计算 REQ_AUTH 的验证字
	// MD5( Header + Attrs + Secret )
	auth = calcAuthenticator(buf.Bytes(), secret)
	copy(buf.Bytes()[16:], auth) // 填回第 16-32 字节

	fmt.Printf("[Portal-CHAP] 3. Sending REQ_AUTH (User: %s)...\n", username)
	if _, err := conn.Write(buf.Bytes()); err != nil { return err }

	return nil
}
