//go:build darwin
// +build darwin

package core

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Initialization of functions for Darwin (macOS)
func init() {
	createTunTapDeviceDarwin = darwinCreateTunTapDevice
	setDeviceMTUDarwin = darwinSetDeviceMTU
	setDeviceUpDarwin = darwinSetDeviceUp
	setDeviceAddressDarwin = darwinSetDeviceAddress
	addDeviceRouteDarwin = darwinAddDeviceRoute
}

// Creates a TUN/TAP device on macOS
func darwinCreateTunTapDevice(config TunTapConfig) (*TunTapDevice, error) {
	// On macOS, only TUN devices are supported via utun
	if config.DeviceType != string(DeviceTUN) {
		return nil, fmt.Errorf("on macOS, only TUN devices are supported via utun")
	}

	// Define device name
	deviceName := config.Name

	// If name is not specified, find an available device
	if deviceName == "" {
		// On macOS, devices are usually named utunX
		// Start with utun0 and look for the first available device
		for i := 0; i < 10; i++ {
			testName := fmt.Sprintf("utun%d", i)
			if deviceExists(testName) {
				continue
			}
			deviceName = testName
			break
		}

		if deviceName == "" {
			return nil, fmt.Errorf("could not find available utun device")
		}
	}

	// Check that the device name starts with "utun"
	if !strings.HasPrefix(deviceName, "utun") {
		return nil, fmt.Errorf("on macOS, TUN device names must start with 'utun'")
	}

	// On macOS, we need to use a special path to open the device
	tunDevPath := "/dev/" + deviceName

	// Create the device if it doesn't exist
	if !deviceExists(deviceName) {
		// On macOS, the device is created automatically when opening /dev/utunX
		// But we need to make sure we have permissions to do this
		if err := createUtunDevice(deviceName); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", deviceName, err)
		}
	}

	// Open the device
	file, err := os.OpenFile(tunDevPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", tunDevPath, err)
	}

	// Set MTU if specified
	if config.MTU > 0 {
		if err := setDeviceMTUDarwin(deviceName, config.MTU); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	} else {
		// Set standard MTU
		if err := setDeviceMTUDarwin(deviceName, 1500); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set default MTU: %w", err)
		}
	}

	// Bring up the device
	if err := setDeviceUpDarwin(deviceName); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set device up: %w", err)
	}

	return &TunTapDevice{
		name:       deviceName,
		deviceType: DeviceTUN,
		file:       file,
		mtu:        config.MTU,
	}, nil
}

// Checks if a device exists
func deviceExists(deviceName string) bool {
	cmd := exec.Command("ifconfig", deviceName)
	err := cmd.Run()
	return err == nil
}

// Creates a utun device
func createUtunDevice(deviceName string) error {
	// On macOS, utun devices are created automatically when opened
	// But we can check if creation is possible using networksetup
	cmd := exec.Command("networksetup", "-listallhardwareports")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list hardware ports: %w", err)
	}

	// Check if utun is in the device list
	if !strings.Contains(string(output), "Tunneling") {
		return fmt.Errorf("tunneling devices not available")
	}

	return nil
}

// Sets the MTU for a network device on macOS
func darwinSetDeviceMTU(deviceName string, mtu int) error {
	cmd := exec.Command("ifconfig", deviceName, "mtu", strconv.Itoa(mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	return nil
}

// Brings up a device on macOS
func darwinSetDeviceUp(deviceName string) error {
	cmd := exec.Command("ifconfig", deviceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set device up: %w", err)
	}
	return nil
}

// Sets an IP address for a TUN/TAP device on macOS
func darwinSetDeviceAddress(deviceName, ipAddr, netmask string) error {
	cmd := exec.Command("ifconfig", deviceName, ipAddr, ipAddr, "netmask", netmask)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}
	return nil
}

// Adds a route via a TUN/TAP device on macOS
func darwinAddDeviceRoute(network, netmask, gateway string) error {
	cmd := exec.Command("route", "add", "-net", network, "-netmask", netmask, gateway)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	return nil
}
