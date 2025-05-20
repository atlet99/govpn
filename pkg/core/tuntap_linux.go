//go:build linux
// +build linux

package core

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	// TUN/TAP device constants for Linux
	TUNSETIFF     = 0x400454ca
	TUNSETPERSIST = 0x400454cb
	TUNSETOWNER   = 0x400454cc
	TUNSETGROUP   = 0x400454ce

	IFF_TUN   = 0x0001
	IFF_TAP   = 0x0002
	IFF_NO_PI = 0x1000 // No packet information
)

// Creates a TUN/TAP device on Linux
func createTunTapDeviceLinux(config TunTapConfig) (*TunTapDevice, error) {
	var flag int

	// Determine device type
	switch config.DeviceType {
	case string(DeviceTUN):
		flag = IFF_TUN
	case string(DeviceTAP):
		flag = IFF_TAP
	default:
		return nil, ErrInvalidDeviceType
	}

	// Add flag for no packet information
	flag |= IFF_NO_PI

	// Open the TUN/TAP device file
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: /dev/net/tun does not exist", ErrDeviceNotFound)
		}
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	// Prepare the request structure for ioctl
	// The interface name is 16 bytes IFNAMSIZ in if.h
	var ifr [32]byte

	// Copy the device name if specified
	if config.Name != "" {
		copy(ifr[:16], []byte(config.Name))
	}

	// Set the flags
	*(*uint16)(unsafe.Pointer(&ifr[16])) = uint16(flag)

	// Create the device with ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("failed to create TUN/TAP device: %w", errno)
	}

	// Extract the device name assigned by the kernel
	deviceName := strings.Trim(string(ifr[:16]), "\x00")

	// Set device persistence if requested
	if config.Persist {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETPERSIST), 1)
		if errno != 0 {
			file.Close()
			return nil, fmt.Errorf("failed to set device persistence: %w", errno)
		}
	}

	// Set MTU if specified
	if config.MTU > 0 {
		if err := setDeviceMTULinux(deviceName, config.MTU); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set device MTU: %w", err)
		}
	}

	// Set device up
	if err := setDeviceUpLinux(deviceName); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set device up: %w", err)
	}

	return &TunTapDevice{
		name:       deviceName,
		deviceType: DeviceType(config.DeviceType),
		file:       file,
		mtu:        config.MTU,
	}, nil
}

// Sets the MTU for a network device on Linux
func setDeviceMTULinux(deviceName string, mtu int) error {
	cmd := exec.Command("ip", "link", "set", "dev", deviceName, "mtu", strconv.Itoa(mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	return nil
}

// Sets the device up on Linux
func setDeviceUpLinux(deviceName string) error {
	cmd := exec.Command("ip", "link", "set", "dev", deviceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set device up: %w", err)
	}
	return nil
}

// Sets an IP address for the TUN/TAP device on Linux
func setDeviceAddressLinux(deviceName, ipAddr, netmask string) error {
	cmd := exec.Command("ip", "addr", "add", ipAddr+"/"+netmask, "dev", deviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}
	return nil
}

// Adds a route via the TUN/TAP device on Linux
func addDeviceRouteLinux(deviceName, network, netmask string) error {
	cidr := calculateCIDR(netmask)
	cmd := exec.Command("ip", "route", "add", network+"/"+cidr, "dev", deviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	return nil
}

// Calculate CIDR notation from netmask
func calculateCIDR(netmask string) string {
	parts := strings.Split(netmask, ".")

	if len(parts) != 4 {
		return "24" // Default to /24 if invalid format
	}

	var bits int
	for _, part := range parts {
		val, err := strconv.Atoi(part)
		if err != nil {
			continue
		}

		for i := 7; i >= 0; i-- {
			if val&(1<<i) != 0 {
				bits++
			}
		}
	}

	return strconv.Itoa(bits)
}
