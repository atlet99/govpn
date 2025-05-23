package core

import (
	"net"
	"testing"
	"time"
)

func TestServerStatus(t *testing.T) {
	status := ServerStatus{
		Running:      true,
		ClientCount:  5,
		BytesIn:      1024,
		BytesOut:     2048,
		ActiveRoutes: []string{"10.8.0.0/24", "192.168.1.0/24"},
		StartTime:    time.Now().Unix(),
	}

	if !status.Running {
		t.Error("Expected Running to be true")
	}

	if status.ClientCount != 5 {
		t.Errorf("Expected ClientCount 5, got %d", status.ClientCount)
	}

	if status.BytesIn != 1024 {
		t.Errorf("Expected BytesIn 1024, got %d", status.BytesIn)
	}

	if status.BytesOut != 2048 {
		t.Errorf("Expected BytesOut 2048, got %d", status.BytesOut)
	}

	if len(status.ActiveRoutes) != 2 {
		t.Errorf("Expected 2 active routes, got %d", len(status.ActiveRoutes))
	}

	if status.StartTime == 0 {
		t.Error("StartTime should not be zero")
	}
}

func TestClientInfo(t *testing.T) {
	testAddr, err := net.ResolveIPAddr("ip", "192.168.1.100")
	if err != nil {
		t.Fatalf("Failed to resolve test IP: %v", err)
	}

	testIP := net.ParseIP("10.8.0.2")
	if testIP == nil {
		t.Fatal("Failed to parse test IP")
	}

	now := time.Now().Unix()
	client := ClientInfo{
		CommonName:   "test-client",
		RemoteAddr:   testAddr,
		AssignedIP:   testIP,
		ConnectedAt:  now,
		AuthMode:     "certificate",
		VirtualRoute: []string{"10.8.0.0/24"},
		UserID:       "user123",
	}

	if client.CommonName != "test-client" {
		t.Errorf("Expected CommonName 'test-client', got '%s'", client.CommonName)
	}

	if client.RemoteAddr.String() != testAddr.String() {
		t.Errorf("Expected RemoteAddr %s, got %s", testAddr.String(), client.RemoteAddr.String())
	}

	if !client.AssignedIP.Equal(testIP) {
		t.Errorf("Expected AssignedIP %s, got %s", testIP.String(), client.AssignedIP.String())
	}

	if client.ConnectedAt != now {
		t.Errorf("Expected ConnectedAt %d, got %d", now, client.ConnectedAt)
	}

	if client.AuthMode != "certificate" {
		t.Errorf("Expected AuthMode 'certificate', got '%s'", client.AuthMode)
	}

	if len(client.VirtualRoute) != 1 {
		t.Errorf("Expected 1 virtual route, got %d", len(client.VirtualRoute))
	}

	if client.UserID != "user123" {
		t.Errorf("Expected UserID 'user123', got '%s'", client.UserID)
	}
}

func TestConnectionStats(t *testing.T) {
	now := time.Now().Unix()
	stats := ConnectionStats{
		BytesIn:     1000,
		BytesOut:    2000,
		PacketsIn:   10,
		PacketsOut:  20,
		ConnectedAt: now,
	}

	if stats.BytesIn != 1000 {
		t.Errorf("Expected BytesIn 1000, got %d", stats.BytesIn)
	}

	if stats.BytesOut != 2000 {
		t.Errorf("Expected BytesOut 2000, got %d", stats.BytesOut)
	}

	if stats.PacketsIn != 10 {
		t.Errorf("Expected PacketsIn 10, got %d", stats.PacketsIn)
	}

	if stats.PacketsOut != 20 {
		t.Errorf("Expected PacketsOut 20, got %d", stats.PacketsOut)
	}

	if stats.ConnectedAt != now {
		t.Errorf("Expected ConnectedAt %d, got %d", now, stats.ConnectedAt)
	}
}

func TestVPNConnection(t *testing.T) {
	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1194")
	if err != nil {
		t.Fatalf("Failed to resolve local address: %v", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", "192.168.1.100:5000")
	if err != nil {
		t.Fatalf("Failed to resolve remote address: %v", err)
	}

	now := time.Now()
	conn := VPNConnection{
		ID:            "conn-123",
		ClientID:      "client-456",
		StartTime:     now,
		BytesReceived: 500,
		BytesSent:     750,
		RemoteAddr:    remoteAddr,
		LocalAddr:     localAddr,
		Protocol:      "UDP",
	}

	if conn.ID != "conn-123" {
		t.Errorf("Expected ID 'conn-123', got '%s'", conn.ID)
	}

	if conn.ClientID != "client-456" {
		t.Errorf("Expected ClientID 'client-456', got '%s'", conn.ClientID)
	}

	if !conn.StartTime.Equal(now) {
		t.Errorf("Expected StartTime %v, got %v", now, conn.StartTime)
	}

	if conn.BytesReceived != 500 {
		t.Errorf("Expected BytesReceived 500, got %d", conn.BytesReceived)
	}

	if conn.BytesSent != 750 {
		t.Errorf("Expected BytesSent 750, got %d", conn.BytesSent)
	}

	if conn.Protocol != "UDP" {
		t.Errorf("Expected Protocol 'UDP', got '%s'", conn.Protocol)
	}
}

func TestVPNClient(t *testing.T) {
	now := time.Now()
	client := VPNClient{
		ID:               "client-789",
		CommonName:       "test.example.com",
		ConnectionTime:   now,
		LastSeen:         now.Add(5 * time.Minute),
		RealAddress:      "192.168.1.100",
		VirtualAddress:   "10.8.0.5",
		BytesReceived:    1024,
		BytesSent:        2048,
		Connected:        true,
		ActiveConnection: nil,
		Properties:       map[string]string{"version": "2.5", "platform": "linux"},
	}

	if client.ID != "client-789" {
		t.Errorf("Expected ID 'client-789', got '%s'", client.ID)
	}

	if client.CommonName != "test.example.com" {
		t.Errorf("Expected CommonName 'test.example.com', got '%s'", client.CommonName)
	}

	if !client.ConnectionTime.Equal(now) {
		t.Errorf("Expected ConnectionTime %v, got %v", now, client.ConnectionTime)
	}

	if client.RealAddress != "192.168.1.100" {
		t.Errorf("Expected RealAddress '192.168.1.100', got '%s'", client.RealAddress)
	}

	if client.VirtualAddress != "10.8.0.5" {
		t.Errorf("Expected VirtualAddress '10.8.0.5', got '%s'", client.VirtualAddress)
	}

	if !client.Connected {
		t.Error("Expected Connected to be true")
	}

	if len(client.Properties) != 2 {
		t.Errorf("Expected 2 properties, got %d", len(client.Properties))
	}

	if client.Properties["version"] != "2.5" {
		t.Errorf("Expected version '2.5', got '%s'", client.Properties["version"])
	}
}

func TestClientConfig(t *testing.T) {
	config := ClientConfig{
		ServerAddress:     "vpn.example.com",
		ServerPort:        1194,
		Protocol:          "udp",
		CertPath:          "/path/to/client.crt",
		KeyPath:           "/path/to/client.key",
		CAPath:            "/path/to/ca.crt",
		DeviceType:        "tun",
		DeviceName:        "tun0",
		MTU:               1500,
		Username:          "testuser",
		Password:          "testpass",
		OTP:               "123456",
		CipherMode:        "AES-256-GCM",
		AuthDigest:        "SHA256",
		DNS:               []string{"8.8.8.8", "8.8.4.4"},
		Routes:            []string{"192.168.1.0/24"},
		CompressAlgorithm: "lz4",
		LogLevel:          "info",
		LogOutput:         "stdout",
		LogFilePath:       "",
		RunAsDaemon:       false,
		ProfileName:       "work",
		ConfigPath:        "/etc/govpn/work.ovpn",
		ServiceName:       "govpn-client",
		ServiceEnabled:    false,
	}

	if config.ServerAddress != "vpn.example.com" {
		t.Errorf("Expected ServerAddress 'vpn.example.com', got '%s'", config.ServerAddress)
	}

	if config.ServerPort != 1194 {
		t.Errorf("Expected ServerPort 1194, got %d", config.ServerPort)
	}

	if config.Protocol != "udp" {
		t.Errorf("Expected Protocol 'udp', got '%s'", config.Protocol)
	}

	if config.DeviceType != "tun" {
		t.Errorf("Expected DeviceType 'tun', got '%s'", config.DeviceType)
	}

	if config.MTU != 1500 {
		t.Errorf("Expected MTU 1500, got %d", config.MTU)
	}

	if config.CipherMode != "AES-256-GCM" {
		t.Errorf("Expected CipherMode 'AES-256-GCM', got '%s'", config.CipherMode)
	}

	if len(config.DNS) != 2 {
		t.Errorf("Expected 2 DNS servers, got %d", len(config.DNS))
	}

	if len(config.Routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(config.Routes))
	}

	if config.ProfileName != "work" {
		t.Errorf("Expected ProfileName 'work', got '%s'", config.ProfileName)
	}
}

func TestVPNStatus(t *testing.T) {
	now := time.Now().Unix()
	status := VPNStatus{
		State:       "running",
		StartTime:   now,
		ClientCount: 3,
		BytesIn:     1500,
		BytesOut:    3000,
		Uptime:      3600, // 1 hour
	}

	if status.State != "running" {
		t.Errorf("Expected State 'running', got '%s'", status.State)
	}

	if status.StartTime != now {
		t.Errorf("Expected StartTime %d, got %d", now, status.StartTime)
	}

	if status.ClientCount != 3 {
		t.Errorf("Expected ClientCount 3, got %d", status.ClientCount)
	}

	if status.BytesIn != 1500 {
		t.Errorf("Expected BytesIn 1500, got %d", status.BytesIn)
	}

	if status.BytesOut != 3000 {
		t.Errorf("Expected BytesOut 3000, got %d", status.BytesOut)
	}

	if status.Uptime != 3600 {
		t.Errorf("Expected Uptime 3600, got %d", status.Uptime)
	}
}

func TestClientInfoStaticValues(t *testing.T) {
	// Test with nil values and empty data
	client := ClientInfo{
		CommonName:   "",
		RemoteAddr:   nil,
		AssignedIP:   nil,
		ConnectedAt:  0,
		AuthMode:     "",
		VirtualRoute: []string{},
		UserID:       "",
	}

	if client.CommonName != "" {
		t.Error("Expected empty CommonName")
	}

	if client.RemoteAddr != nil {
		t.Error("Expected nil RemoteAddr")
	}

	if client.AssignedIP != nil {
		t.Error("Expected nil AssignedIP")
	}

	if len(client.VirtualRoute) != 0 {
		t.Error("Expected empty VirtualRoute slice")
	}
}

func TestConnectionStatsZeroValues(t *testing.T) {
	stats := ConnectionStats{}

	if stats.BytesIn != 0 {
		t.Errorf("Expected BytesIn 0, got %d", stats.BytesIn)
	}

	if stats.BytesOut != 0 {
		t.Errorf("Expected BytesOut 0, got %d", stats.BytesOut)
	}

	if stats.PacketsIn != 0 {
		t.Errorf("Expected PacketsIn 0, got %d", stats.PacketsIn)
	}

	if stats.PacketsOut != 0 {
		t.Errorf("Expected PacketsOut 0, got %d", stats.PacketsOut)
	}

	if stats.ConnectedAt != 0 {
		t.Errorf("Expected ConnectedAt 0, got %d", stats.ConnectedAt)
	}
}
