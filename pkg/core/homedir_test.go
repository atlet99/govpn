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

	// Check that it's actually a directory
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		t.Errorf("HomeDir() returned invalid directory: %s", home)
	}

	// Platform-specific check
	if runtime.GOOS == "windows" {
		// On Windows should be USERPROFILE or HOMEDRIVE+HOMEPATH
		userProfile := os.Getenv("USERPROFILE")
		homeDrive := os.Getenv("HOMEDRIVE")
		homePath := os.Getenv("HOMEPATH")

		if userProfile != "" && home != userProfile {
			if homeDrive == "" || homePath == "" || home != homeDrive+homePath {
				t.Errorf("HomeDir() returned unexpected path on Windows: %s", home)
			}
		}
	} else {
		// On Unix systems should be HOME
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

	// Check that the first directory is system-wide
	systemDir := DefaultConfigDirs[0]
	if runtime.GOOS == "windows" {
		// On Windows can be different system paths
		if systemDir == "" {
			t.Error("System config directory should not be empty")
		}
	} else {
		expectedSystemDir := "/etc/govpn"
		if systemDir != expectedSystemDir {
			t.Errorf("First config dir should be %s, got %s", expectedSystemDir, systemDir)
		}
	}

	// Check that the second directory is user-specific
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
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "govpn_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test case when file is not found
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{tempDir}
	defer func() { DefaultConfigDirs = originalDirs }()

	_, err = FindConfigFile()
	if err == nil {
		t.Error("Expected error when config file not found")
	}

	// Create config file in temp directory
	configPath := filepath.Join(tempDir, DefaultConfigName)
	if err := os.WriteFile(configPath, []byte("test config"), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Now file should be found
	foundPath, err := FindConfigFile()
	if err != nil {
		t.Errorf("Expected to find config file, got error: %v", err)
	}

	if foundPath != configPath {
		t.Errorf("Expected to find %s, got %s", configPath, foundPath)
	}
}

func TestFindConfigFileInCurrentDir(t *testing.T) {
	// Save original working directory
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Create temporary directory and change to it
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

	// Create config file in current directory
	configPath := filepath.Join(tempDir, DefaultConfigName)
	if err := os.WriteFile(configPath, []byte("test config"), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Temporarily replace DefaultConfigDirs with non-existent paths
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{"/nonexistent/path"}
	defer func() { DefaultConfigDirs = originalDirs }()

	// File should be found in current directory
	foundPath, err := FindConfigFile()
	if err != nil {
		t.Errorf("Expected to find config file in current dir, got error: %v", err)
	}

	if foundPath != DefaultConfigName {
		t.Errorf("Expected to find %s, got %s", DefaultConfigName, foundPath)
	}
}

func TestListProfiles(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "govpn_profiles_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create profiles directory
	profilesDir := filepath.Join(tempDir, DefaultProfilesDir)
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatalf("Failed to create profiles dir: %v", err)
	}

	// Create several test profiles
	testProfiles := []string{"work", "home", "mobile"}
	for _, profile := range testProfiles {
		profilePath := filepath.Join(profilesDir, profile+".ovpn")
		if err := os.WriteFile(profilePath, []byte("test profile"), 0644); err != nil {
			t.Fatalf("Failed to create test profile %s: %v", profile, err)
		}
	}

	// Create file with wrong extension (should be ignored)
	invalidPath := filepath.Join(profilesDir, "invalid.txt")
	if err := os.WriteFile(invalidPath, []byte("invalid"), 0644); err != nil {
		t.Fatalf("Failed to create invalid file: %v", err)
	}

	// Create subdirectory (should be ignored)
	subDir := filepath.Join(profilesDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Temporarily replace DefaultConfigDirs
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{tempDir}
	defer func() { DefaultConfigDirs = originalDirs }()

	// Get list of profiles
	profiles, err := ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() returned error: %v", err)
	}

	if len(profiles) != len(testProfiles) {
		t.Errorf("Expected %d profiles, got %d", len(testProfiles), len(profiles))
	}

	// Check that all expected profiles are found
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
	// Create temporary directory without profiles
	tempDir, err := os.MkdirTemp("", "govpn_empty_profiles_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Temporarily replace DefaultConfigDirs
	originalDirs := DefaultConfigDirs
	DefaultConfigDirs = []string{tempDir}
	defer func() { DefaultConfigDirs = originalDirs }()

	// Get list of profiles
	profiles, err := ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() returned error: %v", err)
	}

	if len(profiles) != 0 {
		t.Errorf("Expected 0 profiles, got %d", len(profiles))
	}
}

func TestFileExists(t *testing.T) {
	// Create temporary file
	tempFile, err := os.CreateTemp("", "govpn_file_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	// Test existing file
	if !fileExists(tempFile.Name()) {
		t.Errorf("fileExists() should return true for existing file")
	}

	// Test non-existent file
	if fileExists("/nonexistent/file/path") {
		t.Errorf("fileExists() should return false for non-existent file")
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "govpn_dir_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test directory (should return false for directory)
	if fileExists(tempDir) {
		t.Errorf("fileExists() should return false for directory")
	}
}

func TestDirExists(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "govpn_dir_exists_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test existing directory
	if !dirExists(tempDir) {
		t.Errorf("dirExists() should return true for existing directory")
	}

	// Test non-existent directory
	if dirExists("/nonexistent/directory/path") {
		t.Errorf("dirExists() should return false for non-existent directory")
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", "govpn_file_exists_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	// Test file (should return false for file)
	if dirExists(tempFile.Name()) {
		t.Errorf("dirExists() should return false for file")
	}
}
