//! Post-quantum BFT finality gadget — see `spec/finality.md`.
//!
//! A validator set finalizes cuts of the GHOSTDAG. Votes are ML-DSA signatures,
//! so finality is quantum-safe. PoW provides liveness and picks the chain; this
//! gadget provides the irreversible settlement point government/enterprise use
//! demands. Safety rests on quorum intersection (> 2/3 weight) under an honest
//! super-majority.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");
const pq = @import("../crypto/pq/registry.zig");
const Ghostdag = @import("ghostdag.zig").Ghostdag;

const Hash256 = hashmod.Hash256;
const SchemeTag = pq.SchemeTag;

pub const Cut = struct {
    block: Hash256,
    blue_score: u64,
};

pub const Validator = struct {
    scheme: SchemeTag,
    pubkey: []const u8,
    weight: u64,
};

pub const ValidatorSet = struct {
    validators: []const Validator,
    total_weight: u64,

    pub fn init(validators: []const Validator) ValidatorSet {
        var total: u64 = 0;
        for (validators) |v| total += v.weight;
        return .{ .validators = validators, .total_weight = total };
    }

    /// Strictly more than two thirds of total weight.
    pub fn quorum(self: ValidatorSet) u64 {
        return (2 * self.total_weight) / 3 + 1;
    }
};

pub const FinalityVote = struct {
    validator_index: u32,
    cut_block: Hash256,
    cut_blue_score: u64,
    signature: []const u8,
};

pub const Error = error{
    UnknownValidator,
    InvalidVote,
} || std.mem.Allocator.Error;

pub const SubmitResult = enum { recorded, duplicate, stale, finalized };

/// The message a validator signs to vote for a cut.
pub fn voteMessage(cut: Cut) Hash256 {
    var hasher = hashmod.Hasher.init(.finality_vote);
    hasher.update(&cut.block);
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, cut.blue_score, .little);
    hasher.update(&b);
    return hasher.final();
}

const Tally = struct {
    weight: u64,
    voted: std.DynamicBitSetUnmanaged, // which validators have voted for this cut
};

pub const Gadget = struct {
    gpa: std.mem.Allocator,
    validators: ValidatorSet,
    finality_depth: u64,
    finalized: ?Cut = null,
    tallies: std.AutoHashMapUnmanaged(Hash256, Tally) = .empty,

    pub fn init(gpa: std.mem.Allocator, validators: ValidatorSet, finality_depth: u64) Gadget {
        return .{ .gpa = gpa, .validators = validators, .finality_depth = finality_depth };
    }

    pub fn deinit(self: *Gadget) void {
        self.clearTallies();
        self.tallies.deinit(self.gpa);
    }

    fn clearTallies(self: *Gadget) void {
        var it = self.tallies.iterator();
        while (it.next()) |e| e.value_ptr.voted.deinit(self.gpa);
        self.tallies.clearRetainingCapacity();
    }

    /// The finality candidate cut derived from the current selected chain, or
    /// null if the chain is not yet `finality_depth` deep.
    pub fn candidate(self: *const Gadget, gd: *const Ghostdag) ?Cut {
        const tip = gd.selectedTip() orelse return null;
        const tip_score = gd.get(tip).?.blue_score;
        var cur = tip;
        while (true) {
            const d = gd.get(cur).?;
            if (tip_score - d.blue_score >= self.finality_depth) {
                return .{ .block = cur, .blue_score = d.blue_score };
            }
            cur = d.selected_parent orelse return null;
        }
    }

    /// Verify and record a vote. Advances finalization when a cut reaches quorum.
    pub fn submitVote(self: *Gadget, vote: FinalityVote) Error!SubmitResult {
        if (vote.validator_index >= self.validators.validators.len) return Error.UnknownValidator;
        const v = self.validators.validators[vote.validator_index];

        const cut = Cut{ .block = vote.cut_block, .blue_score = vote.cut_blue_score };
        const msg = voteMessage(cut);
        pq.verify(v.scheme, v.pubkey, &msg, vote.signature) catch return Error.InvalidVote;

        // Monotonicity: never move finalization backwards.
        if (self.finalized) |f| {
            if (cut.blue_score <= f.blue_score) return .stale;
        }

        const gop = try self.tallies.getOrPut(self.gpa, cut.block);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .weight = 0,
                .voted = try std.DynamicBitSetUnmanaged.initEmpty(self.gpa, self.validators.validators.len),
            };
        }
        const t = gop.value_ptr;
        if (t.voted.isSet(vote.validator_index)) return .duplicate;
        t.voted.set(vote.validator_index);
        t.weight += v.weight;

        if (t.weight >= self.validators.quorum()) {
            self.finalized = cut;
            self.clearTallies(); // new epoch begins from the finalized point
            return .finalized;
        }
        return .recorded;
    }

    /// Is `block` within the finalized cut (i.e. irreversible)?
    pub fn isFinalized(self: *const Gadget, gd: *const Ghostdag, block: Hash256) bool {
        const f = self.finalized orelse return false;
        return gd.isAncestorOrSelf(block, f.block);
    }

    /// Would accepting `block` violate finality? True if a cut is finalized and
    /// `block` does not build on it (the finalized cut is not in its past).
    pub fn violatesFinality(self: *const Gadget, gd: *const Ghostdag, block: Hash256) bool {
        const f = self.finalized orelse return false;
        return !gd.isAncestorOrSelf(f.block, block);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Dag = @import("dag.zig").Dag;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

fn h(byte: u8) Hash256 {
    return [_]u8{byte} ** 32;
}

const V = struct {
    kp: MlDsa44.KeyPair,
    pk: [MlDsa44.PublicKey.encoded_length]u8,
    fn init(seed: u8) V {
        const kp = MlDsa44.KeyPair.generateDeterministic([_]u8{seed} ** 32) catch unreachable;
        return .{ .kp = kp, .pk = kp.public_key.toBytes() };
    }
    fn sign(self: V, cut: Cut) [MlDsa44.Signature.encoded_length]u8 {
        const ctx = [_]u8{@intFromEnum(SchemeTag.ml_dsa_44)};
        const msg = voteMessage(cut);
        return (self.kp.signWithContext(&msg, null, &ctx) catch unreachable).toBytes();
    }
};

/// Build a linear chain h(1)..h(len) and its coloring.
fn linearChain(gpa: std.mem.Allocator, len: u8, dag: *Dag, gd: *Ghostdag) !void {
    dag.* = Dag.init(gpa);
    try dag.addBlock(h(1), &.{});
    var i: u8 = 2;
    while (i <= len) : (i += 1) try dag.addBlock(h(i), &.{h(i - 1)});
    gd.* = Ghostdag.init(gpa, dag, 4);
    try gd.compute();
}

test "candidate cut sits finality_depth behind the selected tip" {
    const gpa = testing.allocator;
    var dag: Dag = undefined;
    var gd: Ghostdag = undefined;
    try linearChain(gpa, 6, &dag, &gd);
    defer dag.deinit();
    defer gd.deinit();

    const validators = [_]Validator{}; // not needed for candidate
    var gadget = Gadget.init(gpa, ValidatorSet.init(&validators), 2);
    defer gadget.deinit();

    const cut = gadget.candidate(&gd).?;
    // tip h(6) score 5; depth 2 => cut at score 3 => block h(4).
    try testing.expectEqualSlices(u8, &h(4), &cut.block);
    try testing.expectEqual(@as(u64, 3), cut.blue_score);
}

test "PQ-BFT finalization at the 2/3 quorum, and monotonicity" {
    const gpa = testing.allocator;
    var dag: Dag = undefined;
    var gd: Ghostdag = undefined;
    try linearChain(gpa, 6, &dag, &gd);
    defer dag.deinit();
    defer gd.deinit();

    const vs = [_]V{ V.init(10), V.init(11), V.init(12), V.init(13) };
    var validators: [4]Validator = undefined;
    for (&validators, 0..) |*val, i| val.* = .{ .scheme = .ml_dsa_44, .pubkey = &vs[i].pk, .weight = 1 };
    const set = ValidatorSet.init(&validators);
    try testing.expectEqual(@as(u64, 3), set.quorum()); // > 2/3 of 4

    var gadget = Gadget.init(gpa, set, 2);
    defer gadget.deinit();

    const cut = gadget.candidate(&gd).?;

    // Two votes: recorded, not yet final.
    try testing.expectEqual(SubmitResult.recorded, try gadget.submitVote(.{ .validator_index = 0, .cut_block = cut.block, .cut_blue_score = cut.blue_score, .signature = &vs[0].sign(cut) }));
    try testing.expectEqual(SubmitResult.recorded, try gadget.submitVote(.{ .validator_index = 1, .cut_block = cut.block, .cut_blue_score = cut.blue_score, .signature = &vs[1].sign(cut) }));
    try testing.expect(gadget.finalized == null);

    // Double vote by validator 0 does not count.
    try testing.expectEqual(SubmitResult.duplicate, try gadget.submitVote(.{ .validator_index = 0, .cut_block = cut.block, .cut_blue_score = cut.blue_score, .signature = &vs[0].sign(cut) }));

    // Third distinct validator crosses quorum → finalized.
    try testing.expectEqual(SubmitResult.finalized, try gadget.submitVote(.{ .validator_index = 2, .cut_block = cut.block, .cut_blue_score = cut.blue_score, .signature = &vs[2].sign(cut) }));
    try testing.expectEqualSlices(u8, &h(4), &gadget.finalized.?.block);

    // The finalized cut and its past are final; later blocks are not.
    try testing.expect(gadget.isFinalized(&gd, h(4)));
    try testing.expect(gadget.isFinalized(&gd, h(2)));
    try testing.expect(!gadget.isFinalized(&gd, h(5)));

    // A stale vote for a shallower cut is ignored.
    const shallow = Cut{ .block = h(2), .blue_score = 1 };
    try testing.expectEqual(SubmitResult.stale, try gadget.submitVote(.{ .validator_index = 3, .cut_block = shallow.block, .cut_blue_score = shallow.blue_score, .signature = &vs[3].sign(shallow) }));
    try testing.expectEqualSlices(u8, &h(4), &gadget.finalized.?.block); // unchanged
}

test "invalid signature is rejected" {
    const gpa = testing.allocator;
    var dag: Dag = undefined;
    var gd: Ghostdag = undefined;
    try linearChain(gpa, 6, &dag, &gd);
    defer dag.deinit();
    defer gd.deinit();

    const vs = [_]V{ V.init(20), V.init(21), V.init(22), V.init(23) };
    var validators: [4]Validator = undefined;
    for (&validators, 0..) |*val, i| val.* = .{ .scheme = .ml_dsa_44, .pubkey = &vs[i].pk, .weight = 1 };
    var gadget = Gadget.init(gpa, ValidatorSet.init(&validators), 2);
    defer gadget.deinit();

    const cut = gadget.candidate(&gd).?;
    // Validator 0 presents validator 1's signature — must fail verification.
    try testing.expectError(Error.InvalidVote, gadget.submitVote(.{ .validator_index = 0, .cut_block = cut.block, .cut_blue_score = cut.blue_score, .signature = &vs[1].sign(cut) }));
}

test "safety: two conflicting cuts cannot both reach quorum with honest votes" {
    const gpa = testing.allocator;
    var dag: Dag = undefined;
    var gd: Ghostdag = undefined;
    try linearChain(gpa, 6, &dag, &gd);
    defer dag.deinit();
    defer gd.deinit();

    const vs = [_]V{ V.init(30), V.init(31), V.init(32), V.init(33) };
    var validators: [4]Validator = undefined;
    for (&validators, 0..) |*val, i| val.* = .{ .scheme = .ml_dsa_44, .pubkey = &vs[i].pk, .weight = 1 };
    var gadget = Gadget.init(gpa, ValidatorSet.init(&validators), 2);
    defer gadget.deinit();

    const cut_x = Cut{ .block = h(4), .blue_score = 3 };
    const cut_y = Cut{ .block = h(3), .blue_score = 2 }; // a different, conflicting cut

    // Honest split 2–2: validators 0,1 → X; validators 2,3 → Y. Neither finalizes.
    _ = try gadget.submitVote(.{ .validator_index = 0, .cut_block = cut_x.block, .cut_blue_score = cut_x.blue_score, .signature = &vs[0].sign(cut_x) });
    _ = try gadget.submitVote(.{ .validator_index = 1, .cut_block = cut_x.block, .cut_blue_score = cut_x.blue_score, .signature = &vs[1].sign(cut_x) });
    _ = try gadget.submitVote(.{ .validator_index = 2, .cut_block = cut_y.block, .cut_blue_score = cut_y.blue_score, .signature = &vs[2].sign(cut_y) });
    _ = try gadget.submitVote(.{ .validator_index = 3, .cut_block = cut_y.block, .cut_blue_score = cut_y.blue_score, .signature = &vs[3].sign(cut_y) });
    try testing.expect(gadget.finalized == null); // quorum (3) reached by neither

    // A majority coalition then finalizes exactly one cut.
    try testing.expectEqual(SubmitResult.finalized, try gadget.submitVote(.{ .validator_index = 2, .cut_block = cut_x.block, .cut_blue_score = cut_x.blue_score, .signature = &vs[2].sign(cut_x) }));
    try testing.expectEqualSlices(u8, &h(4), &gadget.finalized.?.block);
}
