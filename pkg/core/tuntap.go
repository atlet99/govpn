// Package core contains VPN server core components
package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

var (
	// ErrDeviceNotSupported is returned when TUN/TAP device is not supported on the system
	ErrDeviceNotSupported = errors.New("tun/tap device is not supported on this system")

	// ErrDeviceNotFound is returned when TUN/TAP device is not found
	ErrDeviceNotFound = errors.New("tun/tap device not found")

	// ErrInvalidDeviceType is returned when invalid device type is requested
	ErrInvalidDeviceType = errors.New("invalid device type, must be 'tun' or 'tap'")
)

// DeviceType represents the type of virtual network device
type DeviceType string

const (
	// DeviceTUN represents a TUN device (layer 3)
	DeviceTUN DeviceType = "tun"

	// DeviceTAP represents a TAP device (layer 2)
	DeviceTAP DeviceType = "tap"
)

// TunTapDevice implements the TunnelDevice interface for TUN/TAP devices
type TunTapDevice struct {
	name       string
	deviceType DeviceType
	file       *os.File
	iface      net.Interface
	mtu        int
	mu         sync.RWMutex
	closed     bool
}

// NewTunTapDevice creates a new TUN/TAP device
func NewTunTapDevice(config TunTapConfig) (TunnelDevice, error) {
	if config.DeviceType != string(DeviceTUN) && config.DeviceType != string(DeviceTAP) {
		return nil, ErrInvalidDeviceType
	}

	// Default MTU if not set
	if config.MTU <= 0 {
		config.MTU = 1500
	}

	dev, err := createTunTapDevice(config)
	if err != nil {
		return nil, err
	}

	return dev, nil
}

// TunTapConfig contains the configuration for a TUN/TAP device
type TunTapConfig struct {
	DeviceType string // "tun" or "tap"
	Name       string // Device name (optional, system may assign one)
	MTU        int    // Maximum Transmission Unit
	Persist    bool   // Whether the device should persist after the program exits
}

// Name returns the device name
func (d *TunTapDevice) Name() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.name
}

// Type returns the device type
func (d *TunTapDevice) Type() string {
	return string(d.deviceType)
}

// Read reads data from the device
func (d *TunTapDevice) Read(p []byte) (n int, err error) {
	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		return 0, io.ErrClosedPipe
	}
	d.mu.RUnlock()

	return d.file.Read(p)
}

// Write writes data to the device
func (d *TunTapDevice) Write(p []byte) (n int, err error) {
	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		return 0, io.ErrClosedPipe
	}
	d.mu.RUnlock()

	return d.file.Write(p)
}

// Close closes the device
func (d *TunTapDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	return d.file.Close()
}

// MTU returns the device MTU
func (d *TunTapDevice) MTU() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.mtu
}

// SetMTU sets the device MTU
func (d *TunTapDevice) SetMTU(mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("invalid MTU: %d", mtu)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return io.ErrClosedPipe
	}

	if err := setDeviceMTU(d.name, mtu); err != nil {
		return err
	}

	d.mtu = mtu
	return nil
}

// GetTunnelDevice is a helper function for creating the appropriate tunnel device
func GetTunnelDevice(config Config) (TunnelDevice, error) {
	tunConfig := TunTapConfig{
		DeviceType: config.DeviceType,
		MTU:        1500, // Default, can be overridden in config
		Persist:    false,
	}

	return NewTunTapDevice(tunConfig)
}
