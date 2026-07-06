//! Core ledger primitives: outpoints, inputs, outputs, segregated witnesses,
//! transactions, and the txid / wtxid / sighash / address commitments.
//!
//! Design invariants baked in here:
//!  - Witnesses are SEGREGATED: the txid commits to the witness-free body only,
//!    so signatures are malleability-free and prunable. The wtxid (used for
//!    relay/dedup) additionally commits to the witnesses.
//!  - The sighash binds the spending input's SCHEME TAG, and the address
//!    commitment binds (scheme, pubkey). Together with the per-scheme signature
//!    context (see pq.verify) this closes downgrade / cross-protocol swaps.
//!  - Addresses are 256-bit commitments — the big PQ public key is only revealed
//!    at spend time, and the address never becomes the weakest link.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");
const pq = @import("../crypto/pq/registry.zig");
const codec = @import("../serialization/codec.zig");
const multisig = @import("multisig.zig");

const Hash256 = hashmod.Hash256;
const SchemeTag = pq.SchemeTag;

/// Upper bounds for decode-time allocation safety (consensus-enforced later).
pub const max_pubkey_len: u32 = 64 * 1024;
pub const max_sig_len: u32 = 64 * 1024;
pub const max_inputs: u32 = 1 << 20;
pub const max_outputs: u32 = 1 << 20;
pub const max_witnesses: u32 = 1 << 20;
pub const max_payload_len: u32 = 1 << 20;

pub const OutPoint = struct {
    txid: Hash256,
    index: u32,

    pub fn encode(self: OutPoint, w: *codec.Writer) !void {
        try w.writeHash(self.txid);
        try w.writeU32(self.index);
    }
    pub fn decode(r: *codec.Reader) !OutPoint {
        return .{ .txid = try r.readHash(), .index = try r.readU32() };
    }
};

pub const Input = struct {
    outpoint: OutPoint,

    pub fn encode(self: Input, w: *codec.Writer) !void {
        try self.outpoint.encode(w);
    }
    pub fn decode(r: *codec.Reader) !Input {
        return .{ .outpoint = try OutPoint.decode(r) };
    }
};

pub const Output = struct {
    value: u64,
    scheme: SchemeTag,
    /// = addressCommitment(scheme, pubkey). The pubkey stays hidden until spend.
    commitment: Hash256,

    pub fn encode(self: Output, w: *codec.Writer) !void {
        try w.writeU64(self.value);
        try w.writeByte(@intFromEnum(self.scheme));
        try w.writeHash(self.commitment);
    }
    pub fn decode(r: *codec.Reader) !Output {
        const value = try r.readU64();
        const scheme: SchemeTag = @enumFromInt(try r.readByte());
        const commitment = try r.readHash();
        return .{ .value = value, .scheme = scheme, .commitment = commitment };
    }
};

/// Segregated witness — relay-only and prunable, never part of the txid.
pub const Witness = struct {
    scheme: SchemeTag,
    pubkey: []const u8,
    signature: []const u8,

    pub fn encode(self: Witness, w: *codec.Writer) !void {
        try w.writeByte(@intFromEnum(self.scheme));
        try w.writeVarBytes(self.pubkey);
        try w.writeVarBytes(self.signature);
    }
    pub fn decode(r: *codec.Reader) !Witness {
        const scheme: SchemeTag = @enumFromInt(try r.readByte());
        const pubkey = try r.readVarBytes(max_pubkey_len);
        const signature = try r.readVarBytes(max_sig_len);
        return .{ .scheme = scheme, .pubkey = pubkey, .signature = signature };
    }
};

pub const Transaction = struct {
    version: u32,
    inputs: []const Input,
    outputs: []const Output,
    witnesses: []const Witness,
    /// Free-form committed data. A coinbase (input-less) transaction MUST carry
    /// the block height here so that two coinbases with identical outputs still
    /// have distinct txids (otherwise their created outpoints would collide).
    payload: []const u8 = &.{},

    /// A coinbase mints new supply: it has no inputs (and therefore no
    /// witnesses). Its value is bounded by the block subsidy at block level.
    pub fn isCoinbase(self: Transaction) bool {
        return self.inputs.len == 0;
    }

    /// Witness-free body — the preimage the txid commits to.
    pub fn encodeBody(self: Transaction, w: *codec.Writer) !void {
        try w.writeU32(self.version);
        try w.writeU32(@intCast(self.inputs.len));
        for (self.inputs) |in| try in.encode(w);
        try w.writeU32(@intCast(self.outputs.len));
        for (self.outputs) |out| try out.encode(w);
        try w.writeVarBytes(self.payload);
    }

    pub fn encodeWitnesses(self: Transaction, w: *codec.Writer) !void {
        try w.writeU32(@intCast(self.witnesses.len));
        for (self.witnesses) |wit| try wit.encode(w);
    }

    /// Decode a full transaction (body + witnesses). Arrays are allocated with
    /// `gpa`; variable byte fields reference the reader's buffer, which must
    /// outlive the returned transaction.
    pub fn decode(r: *codec.Reader, gpa: std.mem.Allocator) !Transaction {
        const version = try r.readU32();
        const in_count = try r.readU32();
        if (in_count > max_inputs) return codec.ReadError.TooLarge;
        const inputs = try gpa.alloc(Input, in_count);
        errdefer gpa.free(inputs);
        for (inputs) |*i| i.* = try Input.decode(r);

        const out_count = try r.readU32();
        if (out_count > max_outputs) return codec.ReadError.TooLarge;
        const outputs = try gpa.alloc(Output, out_count);
        errdefer gpa.free(outputs);
        for (outputs) |*o| o.* = try Output.decode(r);

        const payload = try r.readVarBytes(max_payload_len);

        const w_count = try r.readU32();
        if (w_count > max_witnesses) return codec.ReadError.TooLarge;
        const witnesses = try gpa.alloc(Witness, w_count);
        errdefer gpa.free(witnesses);
        for (witnesses) |*wi| wi.* = try Witness.decode(r);

        return .{ .version = version, .inputs = inputs, .outputs = outputs, .witnesses = witnesses, .payload = payload };
    }

    pub fn txid(self: Transaction, gpa: std.mem.Allocator) !Hash256 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try self.encodeBody(&w);
        return hashmod.hash(.txid, list.items);
    }

    pub fn wtxid(self: Transaction, gpa: std.mem.Allocator) !Hash256 {
        const id = try self.txid(gpa);
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try w.writeHash(id);
        try self.encodeWitnesses(&w);
        return hashmod.hash(.wtxid, list.items);
    }

    /// SIGHASH_ALL-style: commit to the whole witness-free body plus the scheme
    /// tag of the input being signed. Binding the tag here means a signature is
    /// valid for exactly one scheme and cannot be replayed under a weaker one.
    pub fn sighash(self: Transaction, gpa: std.mem.Allocator, scheme: SchemeTag) !Hash256 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try w.writeByte(@intFromEnum(scheme));
        try self.encodeBody(&w);
        return hashmod.hash(.sighash, list.items);
    }
};

/// Address commitment binds BOTH the scheme tag and the public key, so an
/// output can only be spent by that exact (scheme, pubkey) pair — no swap to a
/// weaker scheme, no key substitution.
pub fn addressCommitment(scheme: SchemeTag, pubkey: []const u8) Hash256 {
    var h = hashmod.Hasher.init(.address);
    h.update(&[_]u8{@intFromEnum(scheme)});
    h.update(pubkey);
    return h.final();
}

pub const SpendError = multisig.Error; // includes CommitmentMismatch, pq.Error, codec errors

/// Verify that `witness` authorises spending an output with `expected_commitment`,
/// given the transaction's `sighash_msg`. Checks the (scheme, pubkey) commitment
/// first (cheap), then the post-quantum signature.
pub fn verifySpend(
    witness: Witness,
    expected_commitment: Hash256,
    sighash_msg: Hash256,
) SpendError!void {
    // k-of-n multisig: the witness reveals the policy (in `pubkey`) and supplies
    // the signer set (in `signature`); the output commits to H(multisig, policy).
    if (witness.scheme == .multisig) {
        return multisig.verify(expected_commitment, witness.pubkey, witness.signature, sighash_msg);
    }
    // Single-key spend: the commitment binds (scheme, pubkey), then the signature.
    const derived = addressCommitment(witness.scheme, witness.pubkey);
    if (!std.mem.eql(u8, &derived, &expected_commitment)) return error.CommitmentMismatch;
    try pq.verify(witness.scheme, witness.pubkey, &sighash_msg, witness.signature);
}

const testing = std.testing;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

test "transaction body/witness round-trips and txid ignores witnesses" {
    const gpa = testing.allocator;
    const tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{.{ .value = 42, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = "pk", .signature = "sig" }},
    };

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var bw = codec.Writer{ .list = &body, .gpa = gpa };
    try tx.encodeBody(&bw);

    var r = codec.Reader{ .buf = body.items };
    try testing.expectEqual(@as(u32, 1), try r.readU32());
    try testing.expectEqual(@as(u32, 1), try r.readU32()); // input count
    _ = try Input.decode(&r);
    try testing.expectEqual(@as(u32, 1), try r.readU32()); // output count
    const out = try Output.decode(&r);
    try testing.expectEqual(@as(u64, 42), out.value);
    try testing.expectEqualStrings("", try r.readVarBytes(max_pubkey_len)); // empty payload
    try r.finish();

    // Changing only a witness must NOT change the txid.
    var tx2 = tx;
    tx2.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = "OTHER", .signature = "OTHER" }};
    try testing.expectEqualSlices(u8, &(try tx.txid(gpa)), &(try tx2.txid(gpa)));
}

test "end-to-end: create output, spend it with a real ML-DSA-44 signature" {
    const gpa = testing.allocator;

    // Recipient key pair and the address commitment that locks the output.
    const kp = try MlDsa44.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const pk = kp.public_key.toBytes();
    const commitment = addressCommitment(.ml_dsa_44, &pk);

    // Transaction spending that output.
    const tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{.{ .value = 1000, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{},
    };

    // Signer computes the sighash (tag-bound) and signs with matching context.
    const sh = try tx.sighash(gpa, .ml_dsa_44);
    const ctx = [_]u8{@intFromEnum(SchemeTag.ml_dsa_44)};
    const sig = (try kp.signWithContext(&sh, null, &ctx)).toBytes();

    const witness = Witness{ .scheme = .ml_dsa_44, .pubkey = &pk, .signature = &sig };

    // Valid spend.
    try verifySpend(witness, commitment, sh);

    // Wrong commitment (spending someone else's output) → rejected.
    try testing.expectError(error.CommitmentMismatch, verifySpend(witness, hashmod.zero, sh));

    // Right key, wrong sighash (e.g. attacker altered outputs) → rejected.
    const other_sh = try tx.sighash(gpa, .ml_dsa_65);
    try testing.expectError(pq.Error.InvalidSignature, verifySpend(witness, commitment, other_sh));
}

test "verifySpend authorises a k-of-n multisig spend end-to-end" {
    const gpa = testing.allocator;
    const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;

    // 2-of-3: two ML-DSA-44 keys and one ML-DSA-65 key.
    const kp0 = try MlDsa44.KeyPair.generateDeterministic([_]u8{10} ** 32);
    const kp1 = try MlDsa65.KeyPair.generateDeterministic([_]u8{11} ** 32);
    const kp2 = try MlDsa44.KeyPair.generateDeterministic([_]u8{12} ** 32);
    const pk0 = kp0.public_key.toBytes();
    const pk1 = kp1.public_key.toBytes();
    const pk2 = kp2.public_key.toBytes();

    const parts = [_]multisig.Participant{
        .{ .scheme = .ml_dsa_44, .pubkey = &pk0 },
        .{ .scheme = .ml_dsa_65, .pubkey = &pk1 },
        .{ .scheme = .ml_dsa_44, .pubkey = &pk2 },
    };
    const policy = try multisig.encodePolicy(gpa, 2, &parts);
    defer gpa.free(policy);
    const commitment = multisig.commitment(policy); // == the output's commitment

    // The spend's sighash is bound to the multisig marker scheme.
    const tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{.{ .value = 5, .scheme = .multisig, .commitment = hashmod.zero }},
        .witnesses = &.{},
    };
    const sh = try tx.sighash(gpa, .multisig);

    // Participants 1 and 2 sign (each under their own scheme's context).
    const ctx65 = [_]u8{@intFromEnum(SchemeTag.ml_dsa_65)};
    const ctx44 = [_]u8{@intFromEnum(SchemeTag.ml_dsa_44)};
    const s1 = (try kp1.signWithContext(&sh, null, &ctx65)).toBytes();
    const s2 = (try kp2.signWithContext(&sh, null, &ctx44)).toBytes();
    const signers = try multisig.encodeSigners(gpa, &.{
        .{ .index = 1, .signature = &s1 },
        .{ .index = 2, .signature = &s2 },
    });
    defer gpa.free(signers);

    // The multisig witness rides the normal witness triple.
    const witness = Witness{ .scheme = .multisig, .pubkey = policy, .signature = signers };
    try verifySpend(witness, commitment, sh);

    // Spending a different policy's output → rejected.
    try testing.expectError(error.CommitmentMismatch, verifySpend(witness, hashmod.zero, sh));
}
