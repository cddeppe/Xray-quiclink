package udptimeout

import "sync/atomic"

const DefaultSessionIdleSeconds int64 = 1800

var sessionIdleSeconds atomic.Int64

func SetSessionIdleSeconds(s int64) {
    if s <= 0 {
        sessionIdleSeconds.Store(DefaultSessionIdleSeconds)
        return
    }
    sessionIdleSeconds.Store(s)
}

func SessionIdleSeconds() int64 {
    v := sessionIdleSeconds.Load()
    if v <= 0 {
        return DefaultSessionIdleSeconds
    }
    return v
}
