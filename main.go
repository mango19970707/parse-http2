package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/http2/hpack"
	"log"
	"sync"
	"time"
)

// HTTP/2 帧类型常量
const (
	FrameData         = 0x0
	FrameHeaders      = 0x1
	FramePriority     = 0x2
	FrameRSTStream    = 0x3
	FrameSettings     = 0x4
	FramePushPromise  = 0x5
	FramePing         = 0x6
	FrameGoAway       = 0x7
	FrameWindowUpdate = 0x8
	FrameContinuation = 0x9
)

// ConnectionKey 用于标识连接
type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// HTTP2Stream 表示单个 HTTP/2 流
type HTTP2Stream struct {
	StreamID    uint32
	Headers     map[string]string
	Data        bytes.Buffer
	LastUpdated time.Time
	Complete    bool
	mu          sync.Mutex
}

// HTTP2Connection 表示单个 HTTP/2 连接
type HTTP2Connection struct {
	Key         ConnectionKey
	Streams     map[uint32]*HTTP2Stream
	Decoder     *hpack.Decoder
	LastUpdated time.Time
	mu          sync.RWMutex
}

// HTTP2SessionManager 管理所有连接
type HTTP2SessionManager struct {
	Connections map[ConnectionKey]*HTTP2Connection
	mu          sync.RWMutex
}

// Frame 结构定义
type Frame struct {
	Length   uint32
	Type     uint8
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// 创建新的会话管理器
func NewHTTP2SessionManager() *HTTP2SessionManager {
	manager := &HTTP2SessionManager{
		Connections: make(map[ConnectionKey]*HTTP2Connection),
	}
	go manager.cleanupOldConnections()
	return manager
}

func main() {
	// 打开网络接口
	handle, err := pcap.OpenLive("veth0", 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	manager := NewHTTP2SessionManager()

	for packet := range packetSource.Packets() {
		if isHTTP2Packet(packet) {
			connKey, frame, err := parsePacket(packet)
			if err != nil {
				log.Printf("解析数据包错误: %v", err)
				continue
			}

			// 处理帧
			manager.processFrame(connKey, frame)
		}
	}
}

// parsePacket 解析数据包，返回连接键和帧
func parsePacket(packet gopacket.Packet) (ConnectionKey, *Frame, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return ConnectionKey{}, nil, fmt.Errorf("无效的数据包")
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	connKey := ConnectionKey{
		SrcIP:   ip.SrcIP.String(),
		DstIP:   ip.DstIP.String(),
		SrcPort: uint16(tcp.SrcPort),
		DstPort: uint16(tcp.DstPort),
	}

	frame, err := parseHTTP2Frame(packet)
	if err != nil {
		return connKey, nil, err
	}

	return connKey, frame, nil
}

// isHTTP2Packet 判断数据包是否为 HTTP/2
func isHTTP2Packet(packet gopacket.Packet) bool {
	// 检查 TCP 层
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	// 获取应用层数据
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return false
	}

	payload := appLayer.Payload()
	fmt.Println("===================", len(payload), string(payload))

	// 检查 HTTP/2 特征
	// 1. Client Preface
	if len(payload) >= 24 {
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if bytes.Equal(payload[:24], preface) {
			return true
		}
	}

	// 2. 检查帧头部
	if len(payload) >= 9 {
		frameType := payload[3]
		if frameType <= FrameContinuation {
			return true
		}
	}

	return false
}

// parseHTTP2Frame 解析 HTTP/2 帧
func parseHTTP2Frame(packet gopacket.Packet) (*Frame, error) {
	appLayer := packet.ApplicationLayer()
	data := appLayer.Payload()

	if len(data) < 9 {
		return nil, fmt.Errorf("数据长度不足")
	}

	frame := &Frame{}

	// 解析帧长度 (24位)
	frame.Length = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])

	// 解析帧类型和标志
	frame.Type = data[3]
	frame.Flags = data[4]

	// 解析流ID (31位)
	frame.StreamID = binary.BigEndian.Uint32(data[5:9]) & 0x7fffffff

	// 获取负载
	if len(data) >= 9+int(frame.Length) {
		frame.Payload = data[9 : 9+frame.Length]
	}

	return frame, nil
}

// processFrame 处理单个帧
func (m *HTTP2SessionManager) processFrame(key ConnectionKey, frame *Frame) {
	if frame.Type != FrameHeaders && frame.Type != FrameData {
		return
	}
	m.mu.Lock()
	conn, exists := m.Connections[key]
	if !exists {
		conn = &HTTP2Connection{
			Key:     key,
			Streams: make(map[uint32]*HTTP2Stream),
			Decoder: hpack.NewDecoder(4096, nil),
		}
		m.Connections[key] = conn
	}
	m.mu.Unlock()

	conn.processFrame(frame)
}

// processFrame 处理连接中的帧
func (c *HTTP2Connection) processFrame(frame *Frame) {
	c.mu.Lock()
	stream, exists := c.Streams[frame.StreamID]
	if !exists {
		stream = &HTTP2Stream{
			StreamID:    frame.StreamID,
			Headers:     make(map[string]string),
			LastUpdated: time.Now(),
		}
		c.Streams[frame.StreamID] = stream
	}
	c.mu.Unlock()

	stream.mu.Lock()
	defer stream.mu.Unlock()

	stream.LastUpdated = time.Now()
	c.LastUpdated = time.Now()

	switch frame.Type {
	case FrameHeaders:
		c.processHeaders(stream, frame)
	case FrameData:
		c.processData(stream, frame)
	}

	if frame.Flags&0x1 != 0 { // END_STREAM flag
		stream.Complete = true
		c.printCompleteStream(stream)
	}
}

// processHeaders 处理头部帧
func (c *HTTP2Connection) processHeaders(stream *HTTP2Stream, frame *Frame) {
	headers := make([]hpack.HeaderField, 0)
	c.Decoder.SetEmitFunc(func(hf hpack.HeaderField) {
		headers = append(headers, hf)
	})

	if _, err := c.Decoder.Write(frame.Payload); err != nil {
		log.Printf("解析头部错误: %v", err)
		return
	}

	for _, h := range headers {
		stream.Headers[h.Name] = h.Value
	}
}

// processData 处理数据帧
func (c *HTTP2Connection) processData(stream *HTTP2Stream, frame *Frame) {
	stream.Data.Write(frame.Payload)
}

// printCompleteStream 打印完整的流
func (c *HTTP2Connection) printCompleteStream(stream *HTTP2Stream) {
	fmt.Printf("\n=== Complete HTTP/2 Stream ===\n")
	fmt.Printf("Connection: %s:%d -> %s:%d\n",
		c.Key.SrcIP, c.Key.SrcPort,
		c.Key.DstIP, c.Key.DstPort)
	fmt.Printf("Stream ID: %d\n", stream.StreamID)
	fmt.Println("Headers:")
	for name, value := range stream.Headers {
		fmt.Printf("%s: %s\n", name, value)
	}
	fmt.Println("\nData:")
	fmt.Println(stream.Data.String())
	fmt.Println("===========================\n")
}

// cleanupOldConnections 清理旧连接
func (m *HTTP2SessionManager) cleanupOldConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for key, conn := range m.Connections {
			if now.Sub(conn.LastUpdated) > 10*time.Minute {
				delete(m.Connections, key)
			}
		}
		m.mu.Unlock()
	}
}

// GetConnectionStats 获取连接统计信息
func (m *HTTP2SessionManager) GetConnectionStats() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]map[string]interface{}, 0)
	for key, conn := range m.Connections {
		conn.mu.RLock()
		stat := map[string]interface{}{
			"src_ip":    key.SrcIP,
			"dst_ip":    key.DstIP,
			"src_port":  key.SrcPort,
			"dst_port":  key.DstPort,
			"streams":   len(conn.Streams),
			"last_seen": conn.LastUpdated,
		}
		conn.mu.RUnlock()
		stats = append(stats, stat)
	}
	return stats
}

// FilterConnections 过滤连接
func (m *HTTP2SessionManager) FilterConnections(filter func(ConnectionKey) bool) []*HTTP2Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*HTTP2Connection
	for key, conn := range m.Connections {
		if filter(key) {
			result = append(result, conn)
		}
	}
	return result
}

// 示例过滤器
func createIPFilter(ip string) func(ConnectionKey) bool {
	return func(key ConnectionKey) bool {
		return key.SrcIP == ip || key.DstIP == ip
	}
}

// ExportConnection 导出连接数据
func (c *HTTP2Connection) Export() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	streams := make([]map[string]interface{}, 0)
	for _, stream := range c.Streams {
		streams = append(streams, stream.Export())
	}

	return map[string]interface{}{
		"connection": c.Key,
		"streams":    streams,
		"last_seen":  c.LastUpdated,
	}
}

// Export 导出流数据
func (s *HTTP2Stream) Export() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return map[string]interface{}{
		"stream_id":    s.StreamID,
		"headers":      s.Headers,
		"data":         s.Data.String(),
		"complete":     s.Complete,
		"last_updated": s.LastUpdated,
	}
}
