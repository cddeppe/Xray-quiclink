package freedom

import (
	"sync"
	"testing"
)

type testDcidKey struct {
	cid [20]byte
	len int
}

func TestSyncMapStructKey(t *testing.T) {
	var m sync.Map

	// Create a key
	key := testDcidKey{len: 8}
	copy(key.cid[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Store with connID value
	type connID struct {
		src string
	}
	originalCID := connID{src: "test-conn"}
	m.Store(key, originalCID)

	// Create the SAME key values but different struct instance
	key2 := testDcidKey{len: 8}
	copy(key2.cid[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Load with the new key instance
	val, found := m.Load(key2)
	if !found {
		t.Errorf("sync.Map.Load FAILED for struct key! Same values, different instance.")
		t.Logf("key: %+v", key)
		t.Logf("key2: %+v", key2)
		t.Logf("key == key2: %v", key == key2)
		return
	}

	cid, ok := val.(connID)
	if !ok {
		t.Errorf("type assertion failed: got %T, expected connID", val)
		return
	}

	t.Logf("SUCCESS: sync.Map found the key. Value: %+v", cid)
	t.Logf("key == key2: %v", key == key2)
}
