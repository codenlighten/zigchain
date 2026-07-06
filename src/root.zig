//! ZigChain — post-quantum PoW BlockDAG L1.
//!
//! The consensus core is intentionally pure and dependency-light: `hash`,
//! `pq`, `codec` and `primitives` import nothing but the Zig standard library
//! and each other, take explicit allocators, and are usable headless by the
//! differential fuzzer and the (future) Rust reference implementation.

pub const hash = @import("core/crypto/hash.zig");
pub const pq = @import("core/crypto/pq/registry.zig");
pub const codec = @import("core/serialization/codec.zig");
pub const primitives = @import("core/primitives/types.zig");
pub const utxo = @import("core/ledger/utxo.zig");
pub const sharded_utxo = @import("core/ledger/sharded_utxo.zig");
pub const accumulator = @import("core/ledger/accumulator.zig");
pub const validation = @import("core/ledger/validation.zig");
pub const block_validation = @import("core/ledger/block_validation.zig");
pub const block = @import("core/primitives/block.zig");
pub const dag = @import("core/consensus/dag.zig");
pub const ghostdag = @import("core/consensus/ghostdag.zig");
pub const processor = @import("core/consensus/processor.zig");
pub const mass = @import("core/consensus/mass.zig");
pub const finality = @import("core/consensus/finality.zig");
pub const pow = @import("core/consensus/pow.zig");
pub const chain = @import("core/consensus/chain.zig");
pub const ledger_state = @import("core/consensus/ledger_state.zig");
pub const parallel = @import("core/consensus/parallel.zig");
pub const fees = @import("core/consensus/fees.zig");
pub const mempool = @import("node/mempool.zig");
pub const wire = @import("net/wire.zig");
pub const store = @import("node/store.zig");

test {
    // Pull every module's tests into the root test binary.
    _ = hash;
    _ = pq;
    _ = codec;
    _ = primitives;
    _ = utxo;
    _ = sharded_utxo;
    _ = accumulator;
    _ = validation;
    _ = block_validation;
    _ = block;
    _ = dag;
    _ = ghostdag;
    _ = processor;
    _ = mass;
    _ = finality;
    _ = pow;
    _ = chain;
    _ = ledger_state;
    _ = parallel;
    _ = fees;
    _ = mempool;
    _ = wire;
    _ = store;
    _ = @import("tests/properties.zig");
    _ = @import("sim/simnet.zig");
}
