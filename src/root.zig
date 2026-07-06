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
pub const validation = @import("core/ledger/validation.zig");
pub const block = @import("core/primitives/block.zig");
pub const dag = @import("core/consensus/dag.zig");
pub const ghostdag = @import("core/consensus/ghostdag.zig");
pub const processor = @import("core/consensus/processor.zig");
pub const mass = @import("core/consensus/mass.zig");

test {
    // Pull every module's tests into the root test binary.
    _ = hash;
    _ = pq;
    _ = codec;
    _ = primitives;
    _ = utxo;
    _ = validation;
    _ = block;
    _ = dag;
    _ = ghostdag;
    _ = processor;
    _ = mass;
}
