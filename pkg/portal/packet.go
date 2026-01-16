package portal

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
)

// 华为 Portal V2 协议常量
const (
	ReqChallenge = 0x01
	AckChallenge = 0x02
	ReqAuth      = 0x03
	ReqLogout    = 0x05
	
	AuthPAP      = 0x00
	AuthCHAP     = 0x01
)

type Client struct {
	Conn *net.UDPConn
}

func NewClient(port int) (*Client, error) {
	addr := net.UDPAddr{Port: port, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}
	return &Client{Conn: conn}, nil
}

func (c *Client) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}

func (c *Client) Listen() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := c.Conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("UDP Read Error:", err)
			continue
		}
		// 这里处理 AC 的回包，实际项目中需要根据 SerialNo 分发给对应的请求上下文
		fmt.Printf("Received %d bytes from %s: %x\n", n, addr.String(), buf[:n])
	}
}

// BuildPacket 构建 Portal V2 报文 (参照华为标准)
// Header (16 Bytes): Ver(1) Type(1) AuthType(1) Rsv(1) Serial(2) ReqID(2) UserIP(4) UserPort(2) Err(1) AttrNum(1)
// 注意：Python代码中使用了 !BBBBIIIHH (20字节) 或其他变种。这里使用标准 V2 结构。
func BuildPacket(msgType uint8, serialNo uint16, reqID uint16, userIPStr string, attrNum uint8, attrs []byte, secret string) []byte {
	buf := new(bytes.Buffer)
	
	// 1. 构建头部
	userIP := net.ParseIP(userIPStr).To4()
	if userIP == nil {
		userIP = make([]byte, 4)
	}

	binary.Write(buf, binary.BigEndian, uint8(2))        // Ver = 2
	binary.Write(buf, binary.BigEndian, msgType)         // Type
	binary.Write(buf, binary.BigEndian, uint8(AuthPAP))  // AuthType (Default PAP)
	binary.Write(buf, binary.BigEndian, uint8(0))        // Rsv
	binary.Write(buf, binary.BigEndian, serialNo)        // SerialNo
	binary.Write(buf, binary.BigEndian, reqID)           // ReqID
	buf.Write(userIP)                                    // UserIP (4 bytes)
	binary.Write(buf, binary.BigEndian, uint16(0))       // UserPort
	binary.Write(buf, binary.BigEndian, uint8(0))        // ErrCode
	binary.Write(buf, binary.BigEndian, attrNum)         // AttrNum

	// 2. 计算 Authenticator
	// V2: MD5(Header + Attributes + Secret)
	// 注意：Header 中的 Authenticator 字段本身此时不存在，V2 Authenticator 是跟在 Header 后面的 16 字节
	// 实际上 Header 是 16 字节。然后是 16 字节 Auth，然后是 Attributes。
	
	// 这里的 buf 也就是 "Header"
	auth := md5.New()
	auth.Write(buf.Bytes()) // Header
	auth.Write([]byte(make([]byte, 16))) // 占位 Authenticator (通常置0参与计算，或直接 Header+Attrs+Secret，具体看华为文档)
	// 根据 Python 代码逻辑调整：
	// 很多实现是: Authenticator = MD5(UserIP + Serial + ... + Secret)
	// 我们采用通用做法: MD5(Header + 16 zero bytes + Attributes + Secret)
	auth.Write(attrs)
	auth.Write([]byte(secret))
	authenticator := auth.Sum(nil)

	// 3. 最终组包: Header + Authenticator + Attributes
	finalBuf := new(bytes.Buffer)
	finalBuf.Write(buf.Bytes())
	finalBuf.Write(authenticator)
	finalBuf.Write(attrs)

	return finalBuf.Bytes()
}

func (c *Client) SendChallenge(acIP string, acPort int, serial, reqID uint16, userIP, userMAC, secret string) error {
	// 构造属性 (TLV)
	attrs := new(bytes.Buffer)
	// 这里的 TLV 构造省略，实际需添加 UserIP, MAC 等属性
	
	pkt := BuildPacket(ReqChallenge, serial, reqID, userIP, 0, attrs.Bytes(), secret)
	
	addr := &net.UDPAddr{IP: net.ParseIP(acIP), Port: acPort}
	_, err := c.Conn.WriteToUDP(pkt, addr)
	return err
}

func (c *Client) SendAuth(acIP string, acPort int, serial, reqID uint16, userIP, userMAC, user, pwd, secret string) error {
	attrs := new(bytes.Buffer)
	// 构造属性: Username(1) + Password(2)
	// ... TLV 编码逻辑 ...

	pkt := BuildPacket(ReqAuth, serial, reqID, userIP, 0, attrs.Bytes(), secret)
	addr := &net.UDPAddr{IP: net.ParseIP(acIP), Port: acPort}
	_, err := c.Conn.WriteToUDP(pkt, addr)
	return err
}

func (c *Client) SendLogout(acIP string, acPort int, userIP, userMAC, secret string) error {
	pkt := BuildPacket(ReqLogout, 0, 0, userIP, 0, []byte{}, secret)
	addr := &net.UDPAddr{IP: net.ParseIP(acIP), Port: acPort}
	_, err := c.Conn.WriteToUDP(pkt, addr)
	return err
}
