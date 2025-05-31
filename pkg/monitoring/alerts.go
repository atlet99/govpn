package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AlertLevel alert priority level
type AlertLevel string

const (
	AlertInfo     AlertLevel = "info"
	AlertWarning  AlertLevel = "warning"
	AlertCritical AlertLevel = "critical"
)

// Alert alert structure
type Alert struct {
	ID          string                 `json:"id"`
	Level       AlertLevel             `json:"level"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Component   string                 `json:"component"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// AlertRule rule for creating alerts
type AlertRule struct {
	Name        string                                      `json:"name"`
	Description string                                      `json:"description"`
	Level       AlertLevel                                  `json:"level"`
	Condition   func(metrics map[string]interface{}) bool   `json:"-"`
	Message     func(metrics map[string]interface{}) string `json:"-"`
	Cooldown    time.Duration                               `json:"cooldown"`
	lastFired   time.Time
}

// AlertManager manages alerts and notifications
type AlertManager struct {
	rules       map[string]*AlertRule
	alerts      map[string]*Alert
	subscribers []AlertSubscriber
	logger      *Logger
	monitor     *PerformanceMonitor
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	interval    time.Duration
	mu          sync.RWMutex
}

// AlertSubscriber interface for alert subscribers
type AlertSubscriber interface {
	OnAlert(alert *Alert) error
}

// ConsoleAlertSubscriber outputs alerts to console
type ConsoleAlertSubscriber struct {
	logger *Logger
}

func NewConsoleAlertSubscriber(logger *Logger) *ConsoleAlertSubscriber {
	return &ConsoleAlertSubscriber{logger: logger}
}

func (c *ConsoleAlertSubscriber) OnAlert(alert *Alert) error {
	c.logger.LogSecurityEvent("alert_triggered", string(alert.Level), alert.Description,
		"alert_id", alert.ID,
		"title", alert.Title,
		"component", alert.Component,
	)
	return nil
}

// NewAlertManager creates a new alerts manager
func NewAlertManager(logger *Logger, monitor *PerformanceMonitor, checkInterval time.Duration) *AlertManager {
	ctx, cancel := context.WithCancel(context.Background())

	if checkInterval == 0 {
		checkInterval = 30 * time.Second
	}

	am := &AlertManager{
		rules:       make(map[string]*AlertRule),
		alerts:      make(map[string]*Alert),
		subscribers: make([]AlertSubscriber, 0),
		logger:      logger,
		monitor:     monitor,
		ctx:         ctx,
		cancel:      cancel,
		interval:    checkInterval,
	}

	// Add default rules
	am.addDefaultRules()

	return am
}

// Start starts alerts monitoring
func (am *AlertManager) Start() {
	am.wg.Add(1)
	go am.checkAlerts()

	am.logger.LogSystemEvent("alert_manager_started", "monitoring", "Alert manager started",
		"check_interval", am.interval,
		"rules_count", len(am.rules),
	)
}

// Stop stops alerts monitoring
func (am *AlertManager) Stop() {
	am.cancel()
	am.wg.Wait()

	am.logger.LogSystemEvent("alert_manager_stopped", "monitoring", "Alert manager stopped")
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule *AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.rules[rule.Name] = rule
	am.logger.LogSystemEvent("alert_rule_added", "monitoring", "Alert rule added", "rule_name", rule.Name)
}

// RemoveRule removes an alert rule
func (am *AlertManager) RemoveRule(name string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	delete(am.rules, name)
	am.logger.LogSystemEvent("alert_rule_removed", "monitoring", "Alert rule removed", "rule_name", name)
}

// Subscribe adds a subscriber to alerts
func (am *AlertManager) Subscribe(subscriber AlertSubscriber) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.subscribers = append(am.subscribers, subscriber)
}

// checkAlerts checks alert conditions
func (am *AlertManager) checkAlerts() {
	defer am.wg.Done()

	ticker := time.NewTicker(am.interval)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.evaluateRules()
		}
	}
}

// evaluateRules evaluates all alert rules
func (am *AlertManager) evaluateRules() {
	metrics := am.monitor.GetMetricsSummary()

	am.mu.RLock()
	rules := make([]*AlertRule, 0, len(am.rules))
	for _, rule := range am.rules {
		rules = append(rules, rule)
	}
	am.mu.RUnlock()

	for _, rule := range rules {
		// Check cooldown
		if time.Since(rule.lastFired) < rule.Cooldown {
			continue
		}

		if rule.Condition(metrics) {
			am.triggerAlert(rule, metrics)
			rule.lastFired = time.Now()
		}
	}
}

// triggerAlert creates and sends an alert
func (am *AlertManager) triggerAlert(rule *AlertRule, metrics map[string]interface{}) {
	alert := &Alert{
		ID:          fmt.Sprintf("%s-%d", rule.Name, time.Now().Unix()),
		Level:       rule.Level,
		Title:       rule.Name,
		Description: rule.Message(metrics),
		Component:   "govpn-server",
		Metadata:    metrics,
		Timestamp:   time.Now(),
		Resolved:    false,
	}

	am.mu.Lock()
	am.alerts[alert.ID] = alert
	subscribers := make([]AlertSubscriber, len(am.subscribers))
	copy(subscribers, am.subscribers)
	am.mu.Unlock()

	// Send notifications to subscribers
	for _, subscriber := range subscribers {
		if err := subscriber.OnAlert(alert); err != nil {
			am.logger.LogError("alert_manager", "notify_subscriber", err,
				"alert_id", alert.ID,
				"alert_level", string(alert.Level),
			)
		}
	}

	am.logger.LogSecurityEvent("alert_created", string(alert.Level), alert.Description,
		"alert_id", alert.ID,
		"rule_name", rule.Name,
	)
}

// GetActiveAlerts returns active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts := make([]*Alert, 0)
	for _, alert := range am.alerts {
		if !alert.Resolved {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// ResolveAlert marks an alert as resolved
func (am *AlertManager) ResolveAlert(alertID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert %s not found", alertID)
	}

	if alert.Resolved {
		return fmt.Errorf("alert %s already resolved", alertID)
	}

	now := time.Now()
	alert.Resolved = true
	alert.ResolvedAt = &now

	am.logger.LogSystemEvent("alert_resolved", "monitoring", "Alert resolved",
		"alert_id", alertID,
		"alert_level", string(alert.Level),
	)

	return nil
}

// addDefaultRules adds default alert rules
func (am *AlertManager) addDefaultRules() {
	// High memory usage
	am.AddRule(&AlertRule{
		Name:        "high_memory_usage",
		Description: "High memory usage detected",
		Level:       AlertWarning,
		Cooldown:    5 * time.Minute,
		Condition: func(metrics map[string]interface{}) bool {
			runtime, ok := metrics["runtime"].(map[string]interface{})
			if !ok {
				return false
			}
			memAlloc, ok := runtime["memory_alloc"].(uint64)
			if !ok {
				return false
			}
			// Warning when using more than 500MB
			return memAlloc > 500*1024*1024
		},
		Message: func(metrics map[string]interface{}) string {
			runtime := metrics["runtime"].(map[string]interface{})
			memAlloc := runtime["memory_alloc"].(uint64)
			return fmt.Sprintf("Memory usage is high: %d MB", memAlloc/(1024*1024))
		},
	})

	// Too many goroutines
	am.AddRule(&AlertRule{
		Name:        "high_goroutine_count",
		Description: "High number of goroutines detected",
		Level:       AlertWarning,
		Cooldown:    5 * time.Minute,
		Condition: func(metrics map[string]interface{}) bool {
			runtime, ok := metrics["runtime"].(map[string]interface{})
			if !ok {
				return false
			}
			goroutines, ok := runtime["goroutines"].(int)
			if !ok {
				return false
			}
			// Warning when goroutine count exceeds 1000
			return goroutines > 1000
		},
		Message: func(metrics map[string]interface{}) string {
			runtime := metrics["runtime"].(map[string]interface{})
			goroutines := runtime["goroutines"].(int)
			return fmt.Sprintf("High number of goroutines: %d", goroutines)
		},
	})

	// Frequent obfuscation method switches
	am.AddRule(&AlertRule{
		Name:        "frequent_obfuscation_switches",
		Description: "Frequent obfuscation method switches detected",
		Level:       AlertWarning,
		Cooldown:    10 * time.Minute,
		Condition: func(metrics map[string]interface{}) bool {
			app, ok := metrics["application"].(map[string]interface{})
			if !ok {
				return false
			}
			switches, ok := app["obfuscation_switches"].(int64)
			if !ok {
				return false
			}
			// Warning when more than 10 switches detected in period
			return switches > 10
		},
		Message: func(metrics map[string]interface{}) string {
			app := metrics["application"].(map[string]interface{})
			switches := app["obfuscation_switches"].(int64)
			return fmt.Sprintf("Frequent obfuscation switches detected: %d", switches)
		},
	})

	// DPI blocking detection
	am.AddRule(&AlertRule{
		Name:        "dpi_blocking_detected",
		Description: "DPI blocking activity detected",
		Level:       AlertCritical,
		Cooldown:    30 * time.Minute,
		Condition: func(metrics map[string]interface{}) bool {
			app, ok := metrics["application"].(map[string]interface{})
			if !ok {
				return false
			}
			detections, ok := app["dpi_detections"].(int64)
			if !ok {
				return false
			}
			// Critical alert when DPI blocking detected
			return detections > 0
		},
		Message: func(metrics map[string]interface{}) string {
			app := metrics["application"].(map[string]interface{})
			detections := app["dpi_detections"].(int64)
			return fmt.Sprintf("DPI blocking detected: %d detections", detections)
		},
	})

	// High authentication failure rate
	am.AddRule(&AlertRule{
		Name:        "high_auth_failure_rate",
		Description: "High authentication failure rate detected",
		Level:       AlertCritical,
		Cooldown:    15 * time.Minute,
		Condition: func(metrics map[string]interface{}) bool {
			app, ok := metrics["application"].(map[string]interface{})
			if !ok {
				return false
			}
			authAttempts, ok := app["auth_attempts"].(int64)
			if !ok || authAttempts == 0 {
				return false
			}
			// Simple heuristic - in reality, need to track success/failure ratio
			return authAttempts > 100 // Many authentication attempts may indicate an attack
		},
		Message: func(metrics map[string]interface{}) string {
			app := metrics["application"].(map[string]interface{})
			authAttempts := app["auth_attempts"].(int64)
			return fmt.Sprintf("High number of authentication attempts: %d", authAttempts)
		},
	})
}
