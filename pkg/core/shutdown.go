package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

// ShutdownManager manages graceful shutdown of application components
type ShutdownManager struct {
	components []ShutdownComponent
	timeout    time.Duration
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// ShutdownComponent represents a component that can be gracefully shut down
type ShutdownComponent interface {
	Shutdown(ctx context.Context) error
	Name() string
	Priority() int // Lower numbers shut down first
}

// ComponentWrapper wraps a function as a ShutdownComponent
type ComponentWrapper struct {
	name       string
	priority   int
	shutdownFn func(ctx context.Context) error
}

// Name returns the component name
func (cw *ComponentWrapper) Name() string {
	return cw.name
}

// Priority returns the shutdown priority
func (cw *ComponentWrapper) Priority() int {
	return cw.priority
}

// Shutdown executes the shutdown function
func (cw *ComponentWrapper) Shutdown(ctx context.Context) error {
	return cw.shutdownFn(ctx)
}

// ServerComponent represents a server that can be shut down
type ServerComponent struct {
	name     string
	priority int
	server   interface {
		Shutdown(ctx context.Context) error
	}
}

// NewServerComponent creates a new server component
func NewServerComponent(name string, priority int, server interface {
	Shutdown(ctx context.Context) error
}) *ServerComponent {
	return &ServerComponent{
		name:     name,
		priority: priority,
		server:   server,
	}
}

// Name returns the server component name
func (sc *ServerComponent) Name() string {
	return sc.name
}

// Priority returns the shutdown priority
func (sc *ServerComponent) Priority() int {
	return sc.priority
}

// Shutdown shuts down the server
func (sc *ServerComponent) Shutdown(ctx context.Context) error {
	return sc.server.Shutdown(ctx)
}

// ResourceCleanupComponent handles resource cleanup
type ResourceCleanupComponent struct {
	name      string
	priority  int
	cleanupFn func() error
}

// NewResourceCleanupComponent creates a new resource cleanup component
func NewResourceCleanupComponent(name string, priority int, cleanupFn func() error) *ResourceCleanupComponent {
	return &ResourceCleanupComponent{
		name:      name,
		priority:  priority,
		cleanupFn: cleanupFn,
	}
}

// Name returns the component name
func (rcc *ResourceCleanupComponent) Name() string {
	return rcc.name
}

// Priority returns the shutdown priority
func (rcc *ResourceCleanupComponent) Priority() int {
	return rcc.priority
}

// Shutdown performs resource cleanup
func (rcc *ResourceCleanupComponent) Shutdown(ctx context.Context) error {
	if rcc.cleanupFn != nil {
		return rcc.cleanupFn()
	}
	return nil
}

// ContextManager manages context lifecycle
type ContextManager struct {
	rootCtx    context.Context
	cancelFunc context.CancelFunc
	children   []context.CancelFunc
	mu         sync.RWMutex
}

// NewContextManager creates a new context manager
func NewContextManager() *ContextManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ContextManager{
		rootCtx:    ctx,
		cancelFunc: cancel,
		children:   make([]context.CancelFunc, 0),
	}
}

// CreateChildContext creates a child context
func (cm *ContextManager) CreateChildContext() (context.Context, context.CancelFunc) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	ctx, cancel := context.WithCancel(cm.rootCtx)
	cm.children = append(cm.children, cancel)
	return ctx, cancel
}

// CreateTimeoutContext creates a context with timeout
func (cm *ContextManager) CreateTimeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	ctx, cancel := context.WithTimeout(cm.rootCtx, timeout)
	cm.children = append(cm.children, cancel)
	return ctx, cancel
}

// Shutdown cancels all contexts
func (cm *ContextManager) Shutdown() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Cancel all child contexts first
	for _, cancel := range cm.children {
		cancel()
	}

	// Cancel root context
	cm.cancelFunc()
}

// GetRootContext returns the root context
func (cm *ContextManager) GetRootContext() context.Context {
	return cm.rootCtx
}

// NewShutdownManager creates a new shutdown manager
func NewShutdownManager(timeout time.Duration) *ShutdownManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &ShutdownManager{
		components: make([]ShutdownComponent, 0),
		timeout:    timeout,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Register adds a component to the shutdown manager
func (sm *ShutdownManager) Register(component ShutdownComponent) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.components = append(sm.components, component)

	// Sort components by priority (lower numbers first)
	sort.Slice(sm.components, func(i, j int) bool {
		return sm.components[i].Priority() < sm.components[j].Priority()
	})
}

// RegisterFunc registers a shutdown function as a component
func (sm *ShutdownManager) RegisterFunc(name string, priority int, shutdownFn func(ctx context.Context) error) {
	component := &ComponentWrapper{
		name:       name,
		priority:   priority,
		shutdownFn: shutdownFn,
	}
	sm.Register(component)
}

// RegisterServer registers a server component
func (sm *ShutdownManager) RegisterServer(name string, priority int, server interface {
	Shutdown(ctx context.Context) error
}) {
	component := NewServerComponent(name, priority, server)
	sm.Register(component)
}

// RegisterCleanup registers a cleanup function
func (sm *ShutdownManager) RegisterCleanup(name string, priority int, cleanupFn func() error) {
	component := NewResourceCleanupComponent(name, priority, cleanupFn)
	sm.Register(component)
}

// Shutdown gracefully shuts down all registered components
func (sm *ShutdownManager) Shutdown() error {
	sm.mu.RLock()
	components := make([]ShutdownComponent, len(sm.components))
	copy(components, sm.components)
	sm.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), sm.timeout)
	defer cancel()

	var errors []error

	// Shutdown components sequentially by priority
shutdownLoop:
	for _, component := range components {
		select {
		case <-ctx.Done():
			errors = append(errors, fmt.Errorf("shutdown timeout exceeded"))
			break shutdownLoop
		default:
			if err := component.Shutdown(ctx); err != nil {
				errors = append(errors, fmt.Errorf("failed to shutdown %s: %w", component.Name(), err))
			}
		}
	}

	// Cancel our context
	sm.cancel()

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	return nil
}

// WaitForShutdown waits for shutdown signals and triggers graceful shutdown
func (sm *ShutdownManager) WaitForShutdown() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		fmt.Printf("Received signal %v, initiating graceful shutdown...\n", sig)
		return sm.Shutdown()
	case <-sm.ctx.Done():
		return sm.ctx.Err()
	}
}

// GetComponents returns a copy of registered components
func (sm *ShutdownManager) GetComponents() []ShutdownComponent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	components := make([]ShutdownComponent, len(sm.components))
	copy(components, sm.components)
	return components
}

// GetComponentCount returns the number of registered components
func (sm *ShutdownManager) GetComponentCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.components)
}

// IsShutdown returns true if shutdown has been initiated
func (sm *ShutdownManager) IsShutdown() bool {
	select {
	case <-sm.ctx.Done():
		return true
	default:
		return false
	}
}

// GetContext returns the shutdown manager's context
func (sm *ShutdownManager) GetContext() context.Context {
	return sm.ctx
}

// ShutdownHook represents a function that should be called during shutdown
type ShutdownHook func() error

// HookManager manages shutdown hooks
type HookManager struct {
	hooks []ShutdownHook
	mu    sync.RWMutex
}

// NewHookManager creates a new hook manager
func NewHookManager() *HookManager {
	return &HookManager{
		hooks: make([]ShutdownHook, 0),
	}
}

// AddHook adds a shutdown hook
func (hm *HookManager) AddHook(hook ShutdownHook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.hooks = append(hm.hooks, hook)
}

// ExecuteHooks executes all registered hooks
func (hm *HookManager) ExecuteHooks() []error {
	hm.mu.RLock()
	hooks := make([]ShutdownHook, len(hm.hooks))
	copy(hooks, hm.hooks)
	hm.mu.RUnlock()

	var errors []error
	for i, hook := range hooks {
		if err := hook(); err != nil {
			errors = append(errors, fmt.Errorf("hook %d failed: %w", i, err))
		}
	}

	return errors
}

// GetHookCount returns the number of registered hooks
func (hm *HookManager) GetHookCount() int {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return len(hm.hooks)
}

// DefaultShutdownTimeout is the default timeout for shutdown operations
const DefaultShutdownTimeout = 30 * time.Second

// Global shutdown manager instance
var globalShutdownManager *ShutdownManager
var shutdownOnce sync.Once

// GetGlobalShutdownManager returns the global shutdown manager instance
func GetGlobalShutdownManager() *ShutdownManager {
	shutdownOnce.Do(func() {
		globalShutdownManager = NewShutdownManager(DefaultShutdownTimeout)
	})
	return globalShutdownManager
}

// RegisterGlobalShutdown registers a component with the global shutdown manager
func RegisterGlobalShutdown(component ShutdownComponent) {
	GetGlobalShutdownManager().Register(component)
}

// RegisterGlobalShutdownFunc registers a shutdown function with the global manager
func RegisterGlobalShutdownFunc(name string, priority int, shutdownFn func(ctx context.Context) error) {
	GetGlobalShutdownManager().RegisterFunc(name, priority, shutdownFn)
}

// WaitForGlobalShutdown waits for shutdown signals using the global manager
func WaitForGlobalShutdown() error {
	return GetGlobalShutdownManager().WaitForShutdown()
}
