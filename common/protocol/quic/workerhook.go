package quic

import (
	stdnet "net"
	"sync"
)

type WorkerSCIDHook interface {
	OnServerSCID(serverSCID []byte, browserSrc *stdnet.UDPAddr)
}

var (
	workerHooksMu sync.RWMutex
	workerHooks   []WorkerSCIDHook
)

func RegisterWorkerSCIDHook(h WorkerSCIDHook) {
	if h == nil {
		return
	}
	workerHooksMu.Lock()
	defer workerHooksMu.Unlock()
	workerHooks = append(workerHooks, h)
}

func UnregisterWorkerSCIDHook(h WorkerSCIDHook) {
	if h == nil {
		return
	}
	workerHooksMu.Lock()
	defer workerHooksMu.Unlock()
	for i, h2 := range workerHooks {
		if h2 == h {
			workerHooks = append(workerHooks[:i], workerHooks[i+1:]...)
			return
		}
	}
}

func NotifyServerSCID(serverSCID []byte, browserSrc *stdnet.UDPAddr) {
	if len(serverSCID) == 0 || browserSrc == nil {
		return
	}
	workerHooksMu.RLock()
	hooks := make([]WorkerSCIDHook, len(workerHooks))
	copy(hooks, workerHooks)
	workerHooksMu.RUnlock()
	for _, h := range hooks {
		scidCopy := append([]byte(nil), serverSCID...)
		h.OnServerSCID(scidCopy, browserSrc)
	}
}
