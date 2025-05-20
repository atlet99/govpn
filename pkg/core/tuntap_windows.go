//go:build windows
// +build windows

package core

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Initialization of functions for Windows
func init() {
	createTunTapDeviceWindows = windowsCreateTunTapDevice
	setDeviceMTUWindows = windowsSetDeviceMTU
	setDeviceUpWindows = windowsSetDeviceUp
	setDeviceAddressWindows = windowsSetDeviceAddress
	addDeviceRouteWindows = windowsAddDeviceRoute
}

// Creates a TUN/TAP device on Windows
func windowsCreateTunTapDevice(config TunTapConfig) (*TunTapDevice, error) {
	// On Windows, the TAP-Windows driver is typically used for TUN/TAP devices
	// For programmatic control, we can use the OpenVPN TAP-Windows Adapter interface

	// Define GUID for the device if provided
	componentID := "tap0901" // Standard Component ID for TAP-Windows Adapter V9

	// Search for existing TAP device
	adapters, err := findTapAdapters(componentID)
	if err != nil {
		return nil, fmt.Errorf("failed to find TAP adapters: %w", err)
	}

	if len(adapters) == 0 {
		return nil, fmt.Errorf("no TAP adapters found, please install TAP-Windows driver")
	}

	// Use the first adapter found
	adapterName := adapters[0]
	deviceName := config.Name
	if deviceName == "" {
		deviceName = adapterName
	}

	// On Windows, we use a path like \\.\Global\{adapter-GUID}.tap
	devicePath := fmt.Sprintf("\\\\.\\Global\\%s.tap", adapterName)

	// Open the device
	file, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open TAP device %s: %w", devicePath, err)
	}

	// Set MTU if specified
	if config.MTU > 0 {
		if err := setDeviceMTUWindows(deviceName, config.MTU); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	} else {
		// Set standard MTU
		if err := setDeviceMTUWindows(deviceName, 1500); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set default MTU: %w", err)
		}
	}

	// Bring up the device
	if err := setDeviceUpWindows(deviceName); err != nil {
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

// Finds all TAP adapters in the Windows system
func findTapAdapters(componentID string) ([]string, error) {
	// On Windows, registry is typically used to find TAP adapters
	// Here we use command line to get the list of network adapters
	cmd := exec.Command("netsh", "interface", "show", "interface")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// Look for adapters containing "TAP" in the name
	lines := strings.Split(string(output), "\n")
	var adapters []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "TAP") || strings.Contains(line, "tap") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				adapters = append(adapters, fields[len(fields)-1])
			}
		}
	}

	return adapters, nil
}

// Sets the MTU for a network device on Windows
func windowsSetDeviceMTU(deviceName string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("\"%s\"", deviceName),
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	return nil
}

// Brings up a device on Windows
func windowsSetDeviceUp(deviceName string) error {
	cmd := exec.Command("netsh", "interface", "set", "interface",
		fmt.Sprintf("\"%s\"", deviceName),
		"admin=enabled")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set device up: %w", err)
	}
	return nil
}

// Sets an IP address for a TUN/TAP device on Windows
func windowsSetDeviceAddress(deviceName, ipAddr, netmask string) error {
	// Convert subnet mask to CIDR prefix
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=\"%s\"", deviceName),
		"source=static",
		fmt.Sprintf("addr=%s", ipAddr),
		fmt.Sprintf("mask=%s", netmask))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}
	return nil
}

// Adds a route via a TUN/TAP device on Windows
func windowsAddDeviceRoute(network, netmask, gateway string) error {
	// Convert subnet mask to CIDR prefix
	mask := calculateCIDRWindows(netmask)

	cmd := exec.Command("netsh", "interface", "ipv4", "add", "route",
		fmt.Sprintf("%s/%s", network, mask),
		fmt.Sprintf("interface=\"%s\"", gateway))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	return nil
}

// Calculates CIDR notation from a subnet mask for Windows
func calculateCIDRWindows(netmask string) string {
	parts := strings.Split(netmask, ".")
	if len(parts) != 4 {
		return "24" // Default to /24 if format is invalid
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
