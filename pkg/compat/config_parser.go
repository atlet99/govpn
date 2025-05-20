package compat

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// OpenVPNConfigParserImpl implements the OpenVPNConfigParser interface
type OpenVPNConfigParserImpl struct{}

// NewConfigParser creates a new OpenVPN configuration parser
func NewConfigParser() OpenVPNConfigParser {
	return &OpenVPNConfigParserImpl{}
}

// ParseConfig parses OpenVPN configuration from an io.Reader
func (p *OpenVPNConfigParserImpl) ParseConfig(reader io.Reader) (map[string]interface{}, error) {
	config := make(map[string]interface{})
	scanner := bufio.NewScanner(reader)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Remove comments and handle empty lines
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse directive
		directive, value, err := parseDirective(line)
		if err != nil {
			return nil, fmt.Errorf("error in line %d: %w", lineNumber, err)
		}

		// Add directive to configuration
		addDirectiveToConfig(config, directive, value)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading configuration: %w", err)
	}

	return config, nil
}

// ParseConfigFile parses OpenVPN configuration from a file
func (p *OpenVPNConfigParserImpl) ParseConfigFile(path string) (map[string]interface{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open configuration file: %w", err)
	}
	defer file.Close()

	return p.ParseConfig(file)
}

// parseDirective parses a line into directive and value
func parseDirective(line string) (string, interface{}, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty line")
	}

	directive := parts[0]

	// Directives without values
	if len(parts) == 1 {
		return directive, true, nil
	}

	// Directives with one value
	if len(parts) == 2 {
		return directive, parts[1], nil
	}

	// Directives with multiple values
	return directive, parts[1:], nil
}

// addDirectiveToConfig adds a directive to the configuration
func addDirectiveToConfig(config map[string]interface{}, directive string, value interface{}) {
	// Handle special cases
	switch directive {
	case "port":
		if strValue, ok := value.(string); ok {
			if port, err := strconv.Atoi(strValue); err == nil {
				config[directive] = port
			} else {
				config[directive] = strValue
			}
		} else {
			config[directive] = value
		}
	case "proto":
		config["protocol"] = value
	case "server":
		if strValues, ok := value.([]string); ok && len(strValues) >= 2 {
			config[directive] = strValues
			config["server_network"] = strings.Join([]string{strValues[0], strValues[1]}, " ")
		} else {
			config[directive] = value
		}
	case "push":
		if strValues, ok := value.([]string); ok {
			if pushes, exists := config["push"]; exists {
				if pushSlice, ok := pushes.([]string); ok {
					config["push"] = append(pushSlice, strings.Join(strValues, " "))
				} else {
					config["push"] = []string{strings.Join(strValues, " ")}
				}
			} else {
				config["push"] = []string{strings.Join(strValues, " ")}
			}
		}
	case "route":
		if strValues, ok := value.([]string); ok {
			if routes, exists := config["routes"]; exists {
				if routeSlice, ok := routes.([]string); ok {
					config["routes"] = append(routeSlice, strings.Join(strValues, " "))
				} else {
					config["routes"] = []string{strings.Join(strValues, " ")}
				}
			} else {
				config["routes"] = []string{strings.Join(strValues, " ")}
			}
		}
	case "verb":
		if strValue, ok := value.(string); ok {
			if verbLevel, err := strconv.Atoi(strValue); err == nil {
				config[directive] = verbLevel
				// Convert OpenVPN verbosity levels to logging levels
				switch {
				case verbLevel <= 2:
					config["log_level"] = "error"
				case verbLevel == 3:
					config["log_level"] = "warning"
				case verbLevel == 4:
					config["log_level"] = "info"
				default:
					config["log_level"] = "debug"
				}
			} else {
				config[directive] = strValue
			}
		}
	default:
		config[directive] = value
	}
}
