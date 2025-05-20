// Package core contains VPN server core components
package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
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

// Interface returns the network interface associated with this device
func (d *TunTapDevice) Interface() net.Interface {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.iface
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

// createTunTapDevice creates a TUN/TAP device depending on the operating system
func createTunTapDevice(config TunTapConfig) (*TunTapDevice, error) {
	// Call the appropriate function based on the operating system
	switch runtime.GOOS {
	case "linux":
		return createTunTapDeviceLinux(config)
	case "darwin":
		return createTunTapDeviceDarwin(config)
	case "windows":
		return createTunTapDeviceWindows(config)
	default:
		return nil, fmt.Errorf("%w: %s", ErrDeviceNotSupported, runtime.GOOS)
	}
}

// setDeviceMTU sets the MTU for a network interface depending on the OS
func setDeviceMTU(deviceName string, mtu int) error {
	// Call the appropriate function based on the operating system
	switch runtime.GOOS {
	case "linux":
		return setDeviceMTULinux(deviceName, mtu)
	case "darwin":
		return setDeviceMTUDarwin(deviceName, mtu)
	case "windows":
		return setDeviceMTUWindows(deviceName, mtu)
	default:
		return fmt.Errorf("%w: %s", ErrDeviceNotSupported, runtime.GOOS)
	}
}

// setDeviceUp brings up a network interface depending on the OS
//
//lint:ignore U1000 will be used in the future
func setDeviceUp(deviceName string) error {
	// Call the appropriate function based on the operating system
	switch runtime.GOOS {
	case "linux":
		return setDeviceUpLinux(deviceName)
	case "darwin":
		return setDeviceUpDarwin(deviceName)
	case "windows":
		return setDeviceUpWindows(deviceName)
	default:
		return fmt.Errorf("%w: %s", ErrDeviceNotSupported, runtime.GOOS)
	}
}

// setDeviceAddress sets the IP address for a TUN/TAP device
func setDeviceAddress(deviceName, ipAddr, netmask string) error {
	// Call the appropriate function based on the operating system
	switch runtime.GOOS {
	case "linux":
		return setDeviceAddressLinux(deviceName, ipAddr, netmask)
	case "darwin":
		return setDeviceAddressDarwin(deviceName, ipAddr, netmask)
	case "windows":
		return setDeviceAddressWindows(deviceName, ipAddr, netmask)
	default:
		return fmt.Errorf("%w: %s", ErrDeviceNotSupported, runtime.GOOS)
	}
}

// SetDeviceAddress sets the IP address for a TUN/TAP device (public version)
func SetDeviceAddress(deviceName, ipAddr, netmask string) error {
	return setDeviceAddress(deviceName, ipAddr, netmask)
}

// Route represents a network route
type Route struct {
	Destination string // Network destination in CIDR format (e.g., 192.168.1.0/24)
	Gateway     string // Gateway (e.g., 10.8.0.1)
	Device      string // Device name (e.g., tun0)
	Metric      int    // Route metric
}

// AddRoute adds a route to the operating system's routing table
func AddRoute(route Route) error {
	// Split CIDR into network and mask
	network, ipNet, err := net.ParseCIDR(route.Destination)
	if err != nil {
		return fmt.Errorf("invalid destination CIDR %s: %w", route.Destination, err)
	}

	// Convert mask to x.x.x.x format
	netmask := ipNetToNetmask(ipNet)

	// Call the appropriate function based on the operating system
	switch runtime.GOOS {
	case "linux":
		// Function defined in tuntap_linux.go
		return addDeviceRouteLinux(route.Device, network.String(), netmask)
	case "darwin":
		// Function defined in tuntap_darwin.go
		return addDeviceRouteDarwin(network.String(), netmask, route.Gateway)
	case "windows":
		// Function defined in tuntap_windows.go
		return addDeviceRouteWindows(network.String(), netmask, route.Device)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// SetupRoutesFromConfig configures routes from VPN configuration
func SetupRoutesFromConfig(config Config, tunnelDevice TunnelDevice, gatewayIP string) error {
	for _, routeStr := range config.Routes {
		// If route is specified as CIDR, use it directly
		if strings.Contains(routeStr, "/") {
			route := Route{
				Destination: routeStr,
				Gateway:     gatewayIP,
				Device:      tunnelDevice.Name(),
				Metric:      0,
			}

			if err := AddRoute(route); err != nil {
				return fmt.Errorf("failed to add route %s: %w", routeStr, err)
			}
		} else {
			// If route is specified simply as IP, add with /32 mask
			route := Route{
				Destination: routeStr + "/32",
				Gateway:     gatewayIP,
				Device:      tunnelDevice.Name(),
				Metric:      0,
			}

			if err := AddRoute(route); err != nil {
				return fmt.Errorf("failed to add route %s: %w", routeStr, err)
			}
		}
	}

	return nil
}

// ipNetToNetmask converts net.IPNet to a subnet mask string in the format "255.255.255.0"
func ipNetToNetmask(ipNet *net.IPNet) string {
	mask := ipNet.Mask

	// For IPv4, mask must be 4 bytes
	if len(mask) == 16 {
		// Convert IPv6 mask to IPv4 if possible
		mask = mask[12:]
	}

	// Ensure we have 4 bytes for IPv4
	if len(mask) != 4 {
		return "255.255.255.0" // Default value if something is wrong
	}

	// Convert mask bytes to string
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
