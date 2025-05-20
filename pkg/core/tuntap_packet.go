package core

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Константы для работы с IP-пакетами
const (
	IPv4Version      = 4
	IPv4HeaderSize   = 20
	IPv4VersionShift = 4
	IPv4VersionMask  = 0xF0
	IPv4HdrLenMask   = 0x0F
	IPv4HdrLenUnit   = 4 // Длина заголовка указывается в 32-битных словах (4 байта)
)

// Константы для протоколов
const (
	IPProtoICMP = 1
	IPProtoTCP  = 6
	IPProtoUDP  = 17
)

// Packet представляет пакет, передаваемый через TUN/TAP устройство
type Packet struct {
	Data []byte
}

// NewPacket создаёт новый пакет из байтового среза
func NewPacket(data []byte) *Packet {
	return &Packet{
		Data: data,
	}
}

// IsIPv4 проверяет, является ли пакет IPv4
func (p *Packet) IsIPv4() bool {
	if len(p.Data) < IPv4HeaderSize {
		return false
	}

	version := (p.Data[0] & IPv4VersionMask) >> IPv4VersionShift
	return version == IPv4Version
}

// GetIPv4Version возвращает версию IP
func (p *Packet) GetIPv4Version() uint8 {
	if len(p.Data) < 1 {
		return 0
	}
	return (p.Data[0] & IPv4VersionMask) >> IPv4VersionShift
}

// GetIPv4HeaderLength возвращает длину заголовка IPv4 в байтах
func (p *Packet) GetIPv4HeaderLength() uint8 {
	if len(p.Data) < 1 {
		return 0
	}
	return (p.Data[0] & IPv4HdrLenMask) * IPv4HdrLenUnit
}

// GetIPv4Protocol возвращает протокол пакета IPv4
func (p *Packet) GetIPv4Protocol() uint8 {
	if len(p.Data) < 10 {
		return 0
	}
	return p.Data[9]
}

// GetIPv4SourceIP возвращает исходный IP-адрес пакета IPv4
func (p *Packet) GetIPv4SourceIP() net.IP {
	if len(p.Data) < 16 {
		return nil
	}
	return net.IPv4(p.Data[12], p.Data[13], p.Data[14], p.Data[15])
}

// GetIPv4DestinationIP возвращает целевой IP-адрес пакета IPv4
func (p *Packet) GetIPv4DestinationIP() net.IP {
	if len(p.Data) < 20 {
		return nil
	}
	return net.IPv4(p.Data[16], p.Data[17], p.Data[18], p.Data[19])
}

// GetIPv4PayloadLength возвращает длину полезной нагрузки IPv4
func (p *Packet) GetIPv4PayloadLength() uint16 {
	if len(p.Data) < 4 {
		return 0
	}
	totalLen := binary.BigEndian.Uint16(p.Data[2:4])
	headerLen := uint16(p.GetIPv4HeaderLength())

	if totalLen < headerLen {
		return 0
	}

	return totalLen - headerLen
}

// GetIPv4Payload возвращает полезную нагрузку пакета IPv4
func (p *Packet) GetIPv4Payload() []byte {
	if !p.IsIPv4() {
		return nil
	}

	headerLen := p.GetIPv4HeaderLength()
	if len(p.Data) <= int(headerLen) {
		return nil
	}

	return p.Data[headerLen:]
}

// SetIPv4SourceIP устанавливает исходный IP-адрес IPv4
func (p *Packet) SetIPv4SourceIP(ip net.IP) error {
	if !p.IsIPv4() {
		return fmt.Errorf("not an IPv4 packet")
	}

	if len(p.Data) < 16 {
		return fmt.Errorf("packet too short to set source IP")
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("not a valid IPv4 address")
	}

	copy(p.Data[12:16], ipv4)

	// Recalculate checksum
	p.recalculateIPv4Checksum()

	return nil
}

// SetIPv4DestinationIP устанавливает целевой IP-адрес IPv4
func (p *Packet) SetIPv4DestinationIP(ip net.IP) error {
	if !p.IsIPv4() {
		return fmt.Errorf("not an IPv4 packet")
	}

	if len(p.Data) < 20 {
		return fmt.Errorf("packet too short to set destination IP")
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("not a valid IPv4 address")
	}

	copy(p.Data[16:20], ipv4)

	// Recalculate checksum
	p.recalculateIPv4Checksum()

	return nil
}

// recalculateIPv4Checksum пересчитывает контрольную сумму заголовка IPv4
func (p *Packet) recalculateIPv4Checksum() {
	if !p.IsIPv4() {
		return
	}

	headerLen := p.GetIPv4HeaderLength()
	if len(p.Data) < int(headerLen) {
		return
	}

	// Обнуляем текущую контрольную сумму
	p.Data[10] = 0
	p.Data[11] = 0

	// Вычисляем новую контрольную сумму
	var sum uint32

	// Проходим по заголовку как по последовательности 16-битных слов
	for i := 0; i < int(headerLen); i += 2 {
		if i+1 < int(headerLen) {
			sum += uint32(p.Data[i])<<8 | uint32(p.Data[i+1])
		} else {
			sum += uint32(p.Data[i]) << 8
		}
	}

	// Складываем перенос
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Инвертируем биты
	checksum := ^uint16(sum)

	// Записываем контрольную сумму обратно в заголовок
	p.Data[10] = byte(checksum >> 8)
	p.Data[11] = byte(checksum)
}

// ProcessPacket обрабатывает пакет данных из TUN/TAP устройства
func ProcessPacket(data []byte) (*Packet, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty packet data")
	}

	packet := NewPacket(data)

	// Проверка типа пакета
	if packet.IsIPv4() {
		// Обработка IPv4 пакета
		return packet, nil
	}

	// Пока поддерживаем только IPv4
	return nil, fmt.Errorf("unsupported packet type")
}

// CreateIPv4Packet создаёт новый IPv4 пакет с заданными параметрами
func CreateIPv4Packet(srcIP, dstIP net.IP, protocol uint8, payload []byte) (*Packet, error) {
	srcIPv4 := srcIP.To4()
	dstIPv4 := dstIP.To4()

	if srcIPv4 == nil || dstIPv4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	// Создаём минимальный заголовок IPv4
	headerLen := IPv4HeaderSize
	totalLen := headerLen + len(payload)

	if totalLen > 65535 {
		return nil, fmt.Errorf("packet too large")
	}

	data := make([]byte, totalLen)

	// Заполняем поля заголовка
	data[0] = byte((IPv4Version << IPv4VersionShift) | (headerLen / IPv4HdrLenUnit)) // Версия и длина заголовка
	data[1] = 0                                                                      // Type of Service
	binary.BigEndian.PutUint16(data[2:4], uint16(totalLen))                          // Общая длина
	binary.BigEndian.PutUint16(data[4:6], 0)                                         // Identification
	binary.BigEndian.PutUint16(data[6:8], 0)                                         // Flags & Fragment offset
	data[8] = 64                                                                     // TTL
	data[9] = protocol                                                               // Protocol
	// Checksum будет вычислена позже
	copy(data[12:16], srcIPv4) // Source IP
	copy(data[16:20], dstIPv4) // Destination IP

	// Копируем полезную нагрузку
	copy(data[headerLen:], payload)

	packet := NewPacket(data)
	packet.recalculateIPv4Checksum()

	return packet, nil
}
