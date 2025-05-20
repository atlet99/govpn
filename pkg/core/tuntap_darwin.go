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

// Создаёт TUN/TAP устройство на macOS
func createTunTapDeviceDarwin(config TunTapConfig) (*TunTapDevice, error) {
	// На macOS поддерживаются только TUN устройства через утилиту utun
	if config.DeviceType != string(DeviceTUN) {
		return nil, fmt.Errorf("on macOS, only TUN devices are supported via utun")
	}

	// Определяем имя устройства
	deviceName := config.Name

	// Если имя не задано, ищем доступное устройство
	if deviceName == "" {
		// На macOS устройства обычно называются utunX
		// Начинаем с utun0 и ищем первое доступное
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

	// Проверяем, что имя устройства начинается с "utun"
	if !strings.HasPrefix(deviceName, "utun") {
		return nil, fmt.Errorf("on macOS, TUN device names must start with 'utun'")
	}

	// На macOS нужно использовать специальный путь для открытия устройства
	tunDevPath := "/dev/" + deviceName

	// Создаём устройство, если оно не существует
	if !deviceExists(deviceName) {
		// На macOS создание устройства происходит автоматически при открытии /dev/utunX
		// Но нам нужно убедиться, что у нас есть права на это
		if err := createUtunDevice(deviceName); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", deviceName, err)
		}
	}

	// Открываем устройство
	file, err := os.OpenFile(tunDevPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", tunDevPath, err)
	}

	// Устанавливаем MTU, если задано
	if config.MTU > 0 {
		if err := setDeviceMTUDarwin(deviceName, config.MTU); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	} else {
		// Устанавливаем стандартный MTU
		if err := setDeviceMTUDarwin(deviceName, 1500); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set default MTU: %w", err)
		}
	}

	// Поднимаем устройство
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

// Проверяет, существует ли устройство
func deviceExists(deviceName string) bool {
	cmd := exec.Command("ifconfig", deviceName)
	err := cmd.Run()
	return err == nil
}

// Создаёт utun устройство
func createUtunDevice(deviceName string) error {
	// На macOS устройства utun создаются автоматически при открытии
	// Но можно проверить возможность создания с помощью networksetup
	cmd := exec.Command("networksetup", "-listallhardwareports")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list hardware ports: %w", err)
	}

	// Проверяем, есть ли utun в списке устройств
	if !strings.Contains(string(output), "Tunneling") {
		return fmt.Errorf("tunneling devices not available")
	}

	return nil
}

// Устанавливает MTU для сетевого устройства на macOS
func setDeviceMTUDarwin(deviceName string, mtu int) error {
	cmd := exec.Command("ifconfig", deviceName, "mtu", strconv.Itoa(mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	return nil
}

// Поднимает устройство на macOS
func setDeviceUpDarwin(deviceName string) error {
	cmd := exec.Command("ifconfig", deviceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set device up: %w", err)
	}
	return nil
}

// Устанавливает IP-адрес для TUN/TAP устройства на macOS
func setDeviceAddressDarwin(deviceName, ipAddr, netmask string) error {
	cmd := exec.Command("ifconfig", deviceName, ipAddr, ipAddr, "netmask", netmask)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}
	return nil
}

// Добавляет маршрут через TUN/TAP устройство на macOS
func addDeviceRouteDarwin(network, netmask, gateway string) error {
	cmd := exec.Command("route", "add", "-net", network, "-netmask", netmask, gateway)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	return nil
}
