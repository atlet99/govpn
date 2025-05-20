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

// Создаёт TUN/TAP устройство на Windows
func createTunTapDeviceWindows(config TunTapConfig) (*TunTapDevice, error) {
	// На Windows для создания TUN/TAP устройств обычно используется драйвер TAP-Windows
	// Для программного управления можно использовать интерфейс OpenVPN TAP-Windows Adapter

	// Определяем GUID для устройства, если предоставлен
	componentID := "tap0901" // Стандартный Component ID для TAP-Windows Adapter V9

	// Поиск существующего TAP устройства
	adapters, err := findTapAdapters(componentID)
	if err != nil {
		return nil, fmt.Errorf("failed to find TAP adapters: %w", err)
	}

	if len(adapters) == 0 {
		return nil, fmt.Errorf("no TAP adapters found, please install TAP-Windows driver")
	}

	// Используем первый найденный адаптер
	adapterName := adapters[0]
	deviceName := config.Name
	if deviceName == "" {
		deviceName = adapterName
	}

	// На Windows мы используем путь вида \\.\Global\{адаптер-GUID}.tap
	devicePath := fmt.Sprintf("\\\\.\\Global\\%s.tap", adapterName)

	// Открываем устройство
	file, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open TAP device %s: %w", devicePath, err)
	}

	// Устанавливаем MTU, если задано
	if config.MTU > 0 {
		if err := setDeviceMTUWindows(deviceName, config.MTU); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	} else {
		// Устанавливаем стандартный MTU
		if err := setDeviceMTUWindows(deviceName, 1500); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set default MTU: %w", err)
		}
	}

	// Поднимаем устройство
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

// Находит все TAP-адаптеры в системе Windows
func findTapAdapters(componentID string) ([]string, error) {
	// На Windows для поиска TAP адаптеров обычно используется реестр
	// Здесь мы используем командную строку для получения списка сетевых адаптеров
	cmd := exec.Command("netsh", "interface", "show", "interface")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// Ищем адаптеры, содержащие "TAP" в названии
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

// Устанавливает MTU для сетевого устройства на Windows
func setDeviceMTUWindows(deviceName string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("\"%s\"", deviceName),
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	return nil
}

// Поднимает устройство на Windows
func setDeviceUpWindows(deviceName string) error {
	cmd := exec.Command("netsh", "interface", "set", "interface",
		fmt.Sprintf("\"%s\"", deviceName),
		"admin=enabled")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set device up: %w", err)
	}
	return nil
}

// Устанавливает IP-адрес для TUN/TAP устройства на Windows
func setDeviceAddressWindows(deviceName, ipAddr, netmask string) error {
	// Преобразуем маску подсети в префикс CIDR
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

// Добавляет маршрут через TUN/TAP устройство на Windows
func addDeviceRouteWindows(network, netmask, gateway string) error {
	// Преобразуем маску подсети в префикс CIDR
	mask := calculateCIDRWindows(netmask)

	cmd := exec.Command("netsh", "interface", "ipv4", "add", "route",
		fmt.Sprintf("%s/%s", network, mask),
		fmt.Sprintf("interface=\"%s\"", gateway))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	return nil
}

// Вычисляет CIDR-нотацию из маски подсети для Windows
func calculateCIDRWindows(netmask string) string {
	parts := strings.Split(netmask, ".")

	if len(parts) != 4 {
		return "24" // По умолчанию /24 если неверный формат
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
