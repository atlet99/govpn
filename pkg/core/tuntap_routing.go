package core

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// Route представляет сетевой маршрут
type Route struct {
	Destination string // Сеть назначения в формате CIDR (например, 192.168.1.0/24)
	Gateway     string // Шлюз (например, 10.8.0.1)
	Device      string // Имя устройства (например, tun0)
	Metric      int    // Метрика маршрута
}

// AddRoute добавляет маршрут в таблицу маршрутизации операционной системы
func AddRoute(route Route) error {
	// Разбиваем CIDR на адрес сети и маску
	network, ipNet, err := net.ParseCIDR(route.Destination)
	if err != nil {
		return fmt.Errorf("invalid destination CIDR %s: %w", route.Destination, err)
	}

	// Преобразуем маску в формат x.x.x.x
	netmask := ipNetToNetmask(ipNet)

	// В зависимости от операционной системы вызываем соответствующую функцию
	switch runtime.GOOS {
	case "linux":
		// Функция определена в tuntap_linux.go
		return addDeviceRouteLinux(route.Device, network.String(), netmask)
	case "darwin":
		// Функция определена в tuntap_darwin.go
		return addDeviceRouteDarwin(network.String(), netmask, route.Gateway)
	case "windows":
		// Функция определена в tuntap_windows.go
		return addDeviceRouteWindows(network.String(), netmask, route.Device)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// SetupRoutesFromConfig настраивает маршруты из конфигурации VPN
func SetupRoutesFromConfig(config Config, tunnelDevice TunnelDevice, gatewayIP string) error {
	for _, routeStr := range config.Routes {
		// Если маршрут указан как CIDR, используем его напрямую
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
			// Если маршрут указан просто как IP, то добавляем с маской /32
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

// ipNetToNetmask преобразует net.IPNet в строку маски подсети вида "255.255.255.0"
func ipNetToNetmask(ipNet *net.IPNet) string {
	mask := ipNet.Mask

	// Для IPv4 маска должна быть из 4 байт
	if len(mask) == 16 {
		// Преобразуем маску IPv6 в IPv4 если возможно
		mask = mask[12:]
	}

	// Убедимся, что у нас есть 4 байта для IPv4
	if len(mask) != 4 {
		return "255.255.255.0" // Значение по умолчанию, если что-то не так
	}

	// Преобразуем байты маски в строку
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// SetDeviceAddress устанавливает IP-адрес для TUN/TAP устройства
func SetDeviceAddress(deviceName, ipAddr, netmask string) error {
	// В зависимости от операционной системы вызываем соответствующую функцию
	switch runtime.GOOS {
	case "linux":
		// Функция определена в tuntap_linux.go
		return setDeviceAddressLinux(deviceName, ipAddr, netmask)
	case "darwin":
		// Функция определена в tuntap_darwin.go
		return setDeviceAddressDarwin(deviceName, ipAddr, netmask)
	case "windows":
		// Функция определена в tuntap_windows.go
		return setDeviceAddressWindows(deviceName, ipAddr, netmask)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// createTunTapDevice создает TUN/TAP устройство в зависимости от операционной системы
func createTunTapDevice(config TunTapConfig) (*TunTapDevice, error) {
	// В зависимости от операционной системы вызываем соответствующую функцию
	switch runtime.GOOS {
	case "linux":
		// Функция определена в tuntap_linux.go
		return createTunTapDeviceLinux(config)
	case "darwin":
		// Функция определена в tuntap_darwin.go
		return createTunTapDeviceDarwin(config)
	case "windows":
		// Функция определена в tuntap_windows.go
		return createTunTapDeviceWindows(config)
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// setDeviceMTU устанавливает MTU для сетевого интерфейса в зависимости от ОС
func setDeviceMTU(deviceName string, mtu int) error {
	// В зависимости от операционной системы вызываем соответствующую функцию
	switch runtime.GOOS {
	case "linux":
		// Функция определена в tuntap_linux.go
		return setDeviceMTULinux(deviceName, mtu)
	case "darwin":
		// Функция определена в tuntap_darwin.go
		return setDeviceMTUDarwin(deviceName, mtu)
	case "windows":
		// Функция определена в tuntap_windows.go
		return setDeviceMTUWindows(deviceName, mtu)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// setDeviceUp поднимает сетевой интерфейс в зависимости от ОС
func setDeviceUp(deviceName string) error {
	switch runtime.GOOS {
	case "linux":
		// Функция определена в tuntap_linux.go
		return setDeviceUpLinux(deviceName)
	case "darwin":
		// Функция определена в tuntap_darwin.go
		return setDeviceUpDarwin(deviceName)
	case "windows":
		// Функция определена в tuntap_windows.go
		return setDeviceUpWindows(deviceName)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}
