// Package core contains VPN server core components
package core

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

var (
	// ErrInvalidRouteFormat is returned when the route format is invalid
	ErrInvalidRouteFormat = errors.New("invalid route format, expected CIDR notation or IP address")

	// ErrRouteAlreadyExists is returned when adding a route that already exists
	ErrRouteAlreadyExists = errors.New("route already exists")

	// ErrRouteNotFound is returned when a route is not found
	ErrRouteNotFound = errors.New("route not found")
)

// RouteTable manages IP routes for the VPN server
type RouteTable struct {
	mu     sync.RWMutex
	routes map[string]*Route // map[destination]Route
}

// NewRouteTable creates a new route table
func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[string]*Route),
	}
}

// AddRoute adds a route to the routing table
func (rt *RouteTable) AddRoute(route Route) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Validate route format
	if route.Destination == "" {
		return ErrInvalidRouteFormat
	}

	// Add CIDR if not present
	if !strings.Contains(route.Destination, "/") {
		route.Destination = route.Destination + "/32"
	}

	// Parse CIDR to validate it
	_, _, err := net.ParseCIDR(route.Destination)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Check if route already exists
	if _, exists := rt.routes[route.Destination]; exists {
		return ErrRouteAlreadyExists
	}

	// Add route to the routing table
	rt.routes[route.Destination] = &route
	return nil
}

// RemoveRoute removes a route from the routing table
func (rt *RouteTable) RemoveRoute(destination string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Add CIDR if not present
	if !strings.Contains(destination, "/") {
		destination = destination + "/32"
	}

	if _, exists := rt.routes[destination]; !exists {
		return ErrRouteNotFound
	}

	delete(rt.routes, destination)
	return nil
}

// GetAllRoutes returns all routes from the routing table
func (rt *RouteTable) GetAllRoutes() []Route {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	routes := make([]Route, 0, len(rt.routes))
	for _, route := range rt.routes {
		routes = append(routes, *route)
	}

	return routes
}

// LookupRoute finds the appropriate route for a given destination IP
func (rt *RouteTable) LookupRoute(destIP net.IP) *Route {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var bestMatch *Route
	var bestPrefix int = -1

	for _, route := range rt.routes {
		_, ipNet, err := net.ParseCIDR(route.Destination)
		if err != nil {
			continue
		}

		// Check if the destination IP falls within this route's network
		if ipNet.Contains(destIP) {
			// Calculate the size of the network prefix (smaller is more specific)
			prefixLen, _ := ipNet.Mask.Size()

			// Select the most specific route (the one with the longest prefix)
			if prefixLen > bestPrefix {
				bestPrefix = prefixLen
				bestMatch = route
			}
		}
	}

	return bestMatch
}

// ApplyRoutes adds the configured routes to the system routing table
func (rt *RouteTable) ApplyRoutes(device TunnelDevice) error {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	for _, route := range rt.routes {
		// Skip routes that don't have the device field set
		if route.Device == "" {
			route.Device = device.Name()
		}

		// Add the route to the operating system's routing table
		if err := AddRoute(*route); err != nil {
			return fmt.Errorf("failed to apply route %s: %w", route.Destination, err)
		}
	}

	return nil
}

// InitRoutesFromConfig initializes routes from the server configuration
func InitRoutesFromConfig(config Config, device TunnelDevice, gatewayIP string) (*RouteTable, error) {
	rt := NewRouteTable()

	for _, routeStr := range config.Routes {
		// Create a new route
		route := Route{
			Destination: routeStr,
			Gateway:     gatewayIP,
			Device:      device.Name(),
			Metric:      0,
		}

		// Add route to our routing table
		if err := rt.AddRoute(route); err != nil {
			return nil, fmt.Errorf("failed to add route %s: %w", routeStr, err)
		}
	}

	// Apply the routes to the system
	if err := rt.ApplyRoutes(device); err != nil {
		return nil, err
	}

	return rt, nil
}
