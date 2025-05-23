package core

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Standard configuration paths and constants that are shared across platforms
var (
	// DefaultConfigName is the default configuration file name
	DefaultConfigName = "config.ovpn"

	// DefaultProfilesDir is the directory name for profile configurations
	DefaultProfilesDir = "profiles"

	// DefaultConfigDirs is initialized in init() after HomeDir() is available
	DefaultConfigDirs []string
)

func init() {
	// Initialize DefaultConfigDirs here to ensure HomeDir() is available
	DefaultConfigDirs = []string{
		"/etc/govpn",                       // System-wide configuration
		filepath.Join(HomeDir(), ".govpn"), // User configuration
	}

	// On Windows, add Windows-specific paths
	if runtime.GOOS == "windows" {
		programData := os.Getenv("PROGRAMDATA")
		if programData != "" {
			DefaultConfigDirs = append(DefaultConfigDirs, filepath.Join(programData, "GoVPN"))
		}
	}
}

// HomeDir returns the user's home directory for the current platform
func HomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("USERPROFILE")
		if home == "" {
			home = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		}
		return home
	}
	return os.Getenv("HOME")
}

// FindConfigFile looks for a configuration file in standard locations
func FindConfigFile() (string, error) {
	// First check if the file exists in the current directory
	if fileExists(DefaultConfigName) {
		return DefaultConfigName, nil
	}

	// Then check standard paths
	for _, dir := range DefaultConfigDirs {
		path := filepath.Join(dir, DefaultConfigName)
		if fileExists(path) {
			return path, nil
		}
	}

	return "", errors.New("configuration file not found in standard locations")
}

// ListProfiles returns a list of available profiles in standard locations
func ListProfiles() ([]string, error) {
	var profiles []string

	for _, dir := range DefaultConfigDirs {
		profilesDir := filepath.Join(dir, DefaultProfilesDir)

		// Skip if directory doesn't exist
		if !dirExists(profilesDir) {
			continue
		}

		files, err := os.ReadDir(profilesDir)
		if err != nil {
			// Just skip directories that can't be read
			continue
		}

		for _, file := range files {
			if !file.IsDir() && filepath.Ext(file.Name()) == ".ovpn" {
				profileName := strings.TrimSuffix(file.Name(), ".ovpn")
				profiles = append(profiles, profileName)
			}
		}
	}

	return profiles, nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
