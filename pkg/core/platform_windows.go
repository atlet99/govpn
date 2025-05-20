//go:build !windows
// +build !windows

package core

// Функции-заглушки для Windows, используемые при компиляции для других платформ
// Реальные реализации находятся в tuntap_windows.go

func createTunTapDeviceWindows(config TunTapConfig) (*TunTapDevice, error) {
	return nil, ErrDeviceNotSupported
}

func setDeviceMTUWindows(deviceName string, mtu int) error {
	return ErrDeviceNotSupported
}

func setDeviceUpWindows(deviceName string) error {
	return ErrDeviceNotSupported
}

func setDeviceAddressWindows(deviceName, ipAddr, netmask string) error {
	return ErrDeviceNotSupported
}

func addDeviceRouteWindows(network, netmask, gateway string) error {
	return ErrDeviceNotSupported
}
