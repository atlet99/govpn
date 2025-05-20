package core

// platform_stubs.go contains stubs for platform-dependent functions
// These functions will be overridden in platform-specific files (tuntap_linux.go etc.)

// Stubs for Linux
var createTunTapDeviceLinux = func(config TunTapConfig) (*TunTapDevice, error) {
	return nil, ErrDeviceNotSupported
}

var setDeviceMTULinux = func(deviceName string, mtu int) error {
	return ErrDeviceNotSupported
}

//lint:ignore U1000 will be used in platform-specific files
var setDeviceUpLinux = func(deviceName string) error {
	return ErrDeviceNotSupported
}

var setDeviceAddressLinux = func(deviceName, ipAddr, netmask string) error {
	return ErrDeviceNotSupported
}

var addDeviceRouteLinux = func(deviceName, network, netmask string) error {
	return ErrDeviceNotSupported
}

// Stubs for Darwin (macOS)
var createTunTapDeviceDarwin = func(config TunTapConfig) (*TunTapDevice, error) {
	return nil, ErrDeviceNotSupported
}

var setDeviceMTUDarwin = func(deviceName string, mtu int) error {
	return ErrDeviceNotSupported
}

var setDeviceUpDarwin = func(deviceName string) error {
	return ErrDeviceNotSupported
}

var setDeviceAddressDarwin = func(deviceName, ipAddr, netmask string) error {
	return ErrDeviceNotSupported
}

var addDeviceRouteDarwin = func(network, netmask, gateway string) error {
	return ErrDeviceNotSupported
}

// Stubs for Windows
var createTunTapDeviceWindows = func(config TunTapConfig) (*TunTapDevice, error) {
	return nil, ErrDeviceNotSupported
}

var setDeviceMTUWindows = func(deviceName string, mtu int) error {
	return ErrDeviceNotSupported
}

//lint:ignore U1000 will be used in platform-specific files
var setDeviceUpWindows = func(deviceName string) error {
	return ErrDeviceNotSupported
}

var setDeviceAddressWindows = func(deviceName, ipAddr, netmask string) error {
	return ErrDeviceNotSupported
}

var addDeviceRouteWindows = func(network, netmask, gateway string) error {
	return ErrDeviceNotSupported
}
