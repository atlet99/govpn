package core

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHomeDir(t *testing.T) {
	home := HomeDir()

	if home == "" {
		t.Error("HomeDir() should not return empty string")
	}

	// Проверка что это действительно директория
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		t.Errorf("HomeDir() returned invalid directory: %s", home)
	}

	// Проверка специфичная для платформы
	if runtime.GOOS == "windows" {
		// На Windows должен быть USERPROFILE или HOMEDRIVE+HOMEPATH
		userProfile := os.Getenv("USERPROFILE")
		homeDrive := os.Getenv("HOMEDRIVE")
		homePath := os.Getenv("HOMEPATH")

		if userProfile != "" && home != userProfile {
			if homeDrive == "" || homePath == "" || home != homeDrive+homePath {
				t.Errorf("HomeDir() returned unexpected path on Windows: %s", home)
			}
		}
	} else {
		// На Unix-системах должен быть HOME
		expectedHome := os.Getenv("HOME")
		if expectedHome != "" && home != expectedHome {
			t.Errorf("HomeDir() returned %s, expected %s", home, expectedHome)
		}
	}
}

func TestDefaultConfigDirs(t *testing.T) {
	if len(DefaultConfigDirs) == 0 {
		t.Error("DefaultConfigDirs should not be empty")
	}

	// Проверяем что первая директория - системная
	systemDir := DefaultConfigDirs[0]
	if runtime.GOOS == "windows" {
		// На Windows может быть разные системные пути
		if systemDir == "" {
			t.Error("System config directory should not be empty")
		}
	} else {
		expectedSystemDir := "/etc/govpn"
		if systemDir != expectedSystemDir {
			t.Errorf("First config dir should be %s, got %s", expectedSystemDir, systemDir)
		}
	}

	// Проверяем что вторая директория - пользовательская
	if len(DefaultConfigDirs) < 2 {
		t.Error("Should have at least user config directory")
	}

	userDir := DefaultConfigDirs[1]
	expectedUserDir := filepath.Join(HomeDir(), ".govpn")
	if userDir != expectedUserDir {
		t.Errorf("User config dir should be %s, got %s", expectedUserDir, userDir)
	}
}

func TestFindConfigFile(t *testing.T) {
	// Создаем временную директорию для тестов
	tempDir, err := os.MkdirTemp("", "govpn_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Тест случая когда файл не найден
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{tempDir}
	defer func() { DefaultConfigDirs = originalDirs }()

	_, err = FindConfigFile()
	if err == nil {
		t.Error("Expected error when config file not found")
	}

	// Создаем файл конфигурации в temp директории
	configPath := filepath.Join(tempDir, DefaultConfigName)
	if err := os.WriteFile(configPath, []byte("test config"), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Теперь файл должен быть найден
	foundPath, err := FindConfigFile()
	if err != nil {
		t.Errorf("Expected to find config file, got error: %v", err)
	}

	if foundPath != configPath {
		t.Errorf("Expected to find %s, got %s", configPath, foundPath)
	}
}

func TestFindConfigFileInCurrentDir(t *testing.T) {
	// Сохраняем оригинальную рабочую директорию
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Создаем временную директорию и переходим в неё
	tempDir, err := os.MkdirTemp("", "govpn_test_current")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp dir: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Errorf("Failed to restore working directory: %v", err)
		}
	}()

	// Создаем файл конфигурации в текущей директории
	configPath := filepath.Join(tempDir, DefaultConfigName)
	if err := os.WriteFile(configPath, []byte("test config"), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Временно заменяем DefaultConfigDirs на несуществующие пути
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{"/nonexistent/path"}
	defer func() { DefaultConfigDirs = originalDirs }()

	// Файл должен быть найден в текущей директории
	foundPath, err := FindConfigFile()
	if err != nil {
		t.Errorf("Expected to find config file in current dir, got error: %v", err)
	}

	if foundPath != DefaultConfigName {
		t.Errorf("Expected to find %s, got %s", DefaultConfigName, foundPath)
	}
}

func TestListProfiles(t *testing.T) {
	// Создаем временную директорию для тестов
	tempDir, err := os.MkdirTemp("", "govpn_profiles_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Создаем директорию для профилей
	profilesDir := filepath.Join(tempDir, DefaultProfilesDir)
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatalf("Failed to create profiles dir: %v", err)
	}

	// Создаем несколько тестовых профилей
	testProfiles := []string{"work", "home", "mobile"}
	for _, profile := range testProfiles {
		profilePath := filepath.Join(profilesDir, profile+".ovpn")
		if err := os.WriteFile(profilePath, []byte("test profile"), 0644); err != nil {
			t.Fatalf("Failed to create test profile %s: %v", profile, err)
		}
	}

	// Создаем файл с неправильным расширением (должен быть игнорирован)
	invalidPath := filepath.Join(profilesDir, "invalid.txt")
	if err := os.WriteFile(invalidPath, []byte("invalid"), 0644); err != nil {
		t.Fatalf("Failed to create invalid file: %v", err)
	}

	// Создаем поддиректорию (должна быть игнорирована)
	subDir := filepath.Join(profilesDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Временно заменяем DefaultConfigDirs
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{tempDir}
	defer func() { DefaultConfigDirs = originalDirs }()

	// Получаем список профилей
	profiles, err := ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() returned error: %v", err)
	}

	if len(profiles) != len(testProfiles) {
		t.Errorf("Expected %d profiles, got %d", len(testProfiles), len(profiles))
	}

	// Проверяем что все ожидаемые профили найдены
	for _, expected := range testProfiles {
		found := false
		for _, actual := range profiles {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find profile %s", expected)
		}
	}
}

func TestListProfilesEmptyDirectory(t *testing.T) {
	// Создаем временную директорию без профилей
	tempDir, err := os.MkdirTemp("", "govpn_empty_profiles_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Временно заменяем DefaultConfigDirs
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{tempDir}
	defer func() { DefaultConfigDirs = originalDirs }()

	// Получаем список профилей
	profiles, err := ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() returned error: %v", err)
	}

	if len(profiles) != 0 {
		t.Errorf("Expected 0 profiles, got %d", len(profiles))
	}
}

func TestFileExists(t *testing.T) {
	// Создаем временный файл
	tempFile, err := os.CreateTemp("", "govpn_file_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	// Тест существующего файла
	if !fileExists(tempFile.Name()) {
		t.Errorf("fileExists() should return true for existing file")
	}

	// Тест несуществующего файла
	if fileExists("/nonexistent/file/path") {
		t.Errorf("fileExists() should return false for non-existent file")
	}

	// Создаем временную директорию
	tempDir, err := os.MkdirTemp("", "govpn_dir_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Тест директории (должен вернуть false для директории)
	if fileExists(tempDir) {
		t.Errorf("fileExists() should return false for directory")
	}
}

func TestDirExists(t *testing.T) {
	// Создаем временную директорию
	tempDir, err := os.MkdirTemp("", "govpn_dir_exists_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Тест существующей директории
	if !dirExists(tempDir) {
		t.Errorf("dirExists() should return true for existing directory")
	}

	// Тест несуществующей директории
	if dirExists("/nonexistent/directory/path") {
		t.Errorf("dirExists() should return false for non-existent directory")
	}

	// Создаем временный файл
	tempFile, err := os.CreateTemp("", "govpn_file_exists_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	// Тест файла (должен вернуть false для файла)
	if dirExists(tempFile.Name()) {
		t.Errorf("dirExists() should return false for file")
	}
}
