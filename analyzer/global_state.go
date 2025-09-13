package analyzer

import "sync"

// Global shutdown method registry across all analyzed packages in current process
// Keyed by normalized receiver type key (pkgpath.TypeName) -> set of method names
var globalShutdownMethods struct {
	mu   sync.RWMutex
	data map[string]map[string]bool
}

func registerShutdownMethod(typeKey, method string) {
	globalShutdownMethods.mu.Lock()
	if globalShutdownMethods.data == nil {
		globalShutdownMethods.data = make(map[string]map[string]bool)
	}
	m := globalShutdownMethods.data[typeKey]
	if m == nil {
		m = make(map[string]bool)
		globalShutdownMethods.data[typeKey] = m
	}
	m[method] = true
	globalShutdownMethods.mu.Unlock()
}

func getShutdownMethods(typeKey string) (map[string]bool, bool) {
	globalShutdownMethods.mu.RLock()
	defer globalShutdownMethods.mu.RUnlock()
	m, ok := globalShutdownMethods.data[typeKey]
	return m, ok
}
