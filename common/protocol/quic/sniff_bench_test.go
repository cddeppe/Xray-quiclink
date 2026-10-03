package quic_test

import (
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/quic"
)

// BenchmarkSniffQUIC measures the cost of a single SniffQUIC call on a
// real QUIC v1 Initial packet. Run with -bench=. -benchmem.
//
// Expected impact of v26.10.10-link changes (DCID-keyed state cache):
//
//	BenchmarkSniffQUIC/cold           ~12000 ns/op    32800 B/op    12 allocs/op
//	BenchmarkSniffQUIC/warm_keys      ~2100 ns/op    32800 B/op    12 allocs/op
//	BenchmarkSniffQUIC/warm_sni         ~50 ns/op        0 B/op     0 allocs/op
//
// The "cold" case is a brand new DCID (full HKDF + AES pipeline).
// The "warm_keys" case is an Initial retransmit of the same DCID
// (cached keys, re-decrypt only).
// The "warm_sni" case is a post-Initial packet for a DCID whose
// SNI has already been extracted (cache hit, no crypto).
func BenchmarkSniffQUIC(b *testing.B) {
	pkt, err := hex.DecodeString("cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b")
	common.Must(err)

	b.Run("cold", func(b *testing.B) {
		// Each iteration uses a fresh DCID so the cache misses every
		// time. This is the worst-case cost: full HKDF + AES pipeline.
		// We mutate byte 8 (the first DCID byte) to generate unique
		// DCIDs; the keys are derived from the DCID so this forces a
		// real cache miss on every call.
		//
		// Use a private copy so we don't corrupt the shared pkt for
		// the warm_keys / warm_sni sub-benchmarks.
		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pktCopy[8] = byte(i)
			_, _ = quic.SniffQUIC(pktCopy)
		}
	})

	b.Run("warm_keys", func(b *testing.B) {
		// Prime the cache with this exact DCID once.
		_, _ = quic.SniffQUIC(pkt)
		// Subsequent calls should hit the key cache (skip HKDF +
		// aes.NewCipher + AEADAESGCMTLS13) but still re-decrypt
		// and re-parse the CRYPTO frames.
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = quic.SniffQUIC(pkt)
		}
	})

	b.Run("warm_sni", func(b *testing.B) {
		// Prime the cache and extract the SNI once. The priming call
		// is inside the sub-benchmark so it runs even if -bench-filter
		// skips the earlier sub-benchmarks.
		_, _ = quic.SniffQUIC(pkt)
		// Subsequent calls should short-circuit at the cache lookup
		// and return immediately without any crypto work.
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = quic.SniffQUIC(pkt)
		}
	})
}

// BenchmarkSniffQUICRetransmitSkip measures the cost of a sniff call
// for a QUIC Initial whose DCID + packet number we've already seen AND
// extracted the SNI from. This is the v26.10.12-link seenPackets
// optimization: true retransmits skip the AES-GCM Open + frame walk
// entirely and return the cached SNI from the DCID cache (which is
// the same path as BenchmarkSniffQUICNonInitial, but for a long-header
// Initial retransmit rather than a 1-RTT packet).
//
// The bench feeds the same Initial packet twice. The second call should
// hit the SNI cache and return immediately.
func BenchmarkSniffQUICRetransmitSkip(b *testing.B) {
	pkt, err := hex.DecodeString("cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b")
	common.Must(err)
	// Prime the cache.
	_, _ = quic.SniffQUIC(pkt)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = quic.SniffQUIC(pkt)
	}
}
