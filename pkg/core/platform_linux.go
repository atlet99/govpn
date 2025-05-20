//go:build !linux
// +build !linux

package core

// Функции-заглушки для Linux, используемые при компиляции для других платформ
// Реальные реализации находятся в tuntap_linux.go

func createTunTapDeviceLinux(config TunTapConfig) (*TunTapDevice, error) {
	return nil, ErrDeviceNotSupported
}

func setDeviceMTULinux(deviceName string, mtu int) error {
	return ErrDeviceNotSupported
}

func setDeviceUpLinux(deviceName string) error {
	return ErrDeviceNotSupported
}

func setDeviceAddressLinux(deviceName, ipAddr, netmask string) error {
	return ErrDeviceNotSupported
}

func addDeviceRouteLinux(deviceName, network, netmask string) error {
	return ErrDeviceNotSupported
}
