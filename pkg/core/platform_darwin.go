//go:build !darwin
// +build !darwin

package core

// Функции-заглушки для Darwin (macOS), используемые при компиляции для других платформ
// Реальные реализации находятся в tuntap_darwin.go

func createTunTapDeviceDarwin(config TunTapConfig) (*TunTapDevice, error) {
	return nil, ErrDeviceNotSupported
}

func setDeviceMTUDarwin(deviceName string, mtu int) error {
	return ErrDeviceNotSupported
}

func setDeviceUpDarwin(deviceName string) error {
	return ErrDeviceNotSupported
}

func setDeviceAddressDarwin(deviceName, ipAddr, netmask string) error {
	return ErrDeviceNotSupported
}

func addDeviceRouteDarwin(network, netmask, gateway string) error {
	return ErrDeviceNotSupported
}
