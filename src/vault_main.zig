//! Air-gapped custody vault — derive keys, show receive addresses, and sign
//! sighashes offline. The vault needs only a master seed; the online node
//! supplies the sighash to sign and consumes the resulting witness.
//!
//!   zig build vault -- address --seed <hex32> --scheme ml_dsa_44 --path 44/0/0
//!   zig build vault -- sign    --seed <hex32> --scheme sphincs_128f --path 44/0/0 --sighash <hex32>
//!   zig build vault -- verify  --scheme ml_dsa_44 --pubkey <hex> --sighash <hex32> --sig <hex>
//!
//! The remote-signer flow is: the online node computes a transaction's sighash
//! and hands it to `sign`; the vault (holding the seed on an offline machine)
//! returns pubkey+sig; the node assembles the witness. Seeds and secret keys are
//! never emitted.

const std = @import("std");
const linux = std.os.linux;
const registry = @import("core/crypto/pq/registry.zig");
const signer = @import("custody/signer.zig");
const multisig = @import("core/primitives/multisig.zig");

const SchemeTag = registry.SchemeTag;
const Pair = struct { key: []const u8, val: []const u8 };

fn write(bytes: []const u8) void {
    _ = linux.write(1, bytes.ptr, bytes.len);
}
fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    if (std.fmt.bufPrint(&buf, fmt ++ "\n", args)) |s| write(s) else |_| {}
}
fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    out("error: " ++ fmt, args);
    linux.exit(1);
}

/// Write "<label>: <hex>" for an arbitrarily long byte slice (SPHINCS+ sigs are
/// 17 KB → 34 KB of hex, too big for a stack buffer).
fn outHex(gpa: std.mem.Allocator, label: []const u8, bytes: []const u8) void {
    const hex = gpa.alloc(u8, bytes.len * 2) catch fail("oom", .{});
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        hex[2 * i] = digits[b >> 4];
        hex[2 * i + 1] = digits[b & 0x0F];
    }
    write(label);
    write(": ");
    write(hex);
    write("\n");
}

fn hex32(s: []const u8) [32]u8 {
    if (s.len != 64) fail("expected 32-byte hex (64 chars), got {d}", .{s.len});
    var b: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, s) catch fail("bad hex", .{});
    return b;
}

fn parseScheme(s: []const u8) SchemeTag {
    if (std.mem.eql(u8, s, "ml_dsa_44")) return .ml_dsa_44;
    if (std.mem.eql(u8, s, "ml_dsa_65")) return .ml_dsa_65;
    if (std.mem.eql(u8, s, "sphincs_128f")) return .sphincs_shake_128f;
    if (std.mem.eql(u8, s, "sphincs_128s")) return .sphincs_shake_128s;
    fail("unknown scheme '{s}' (ml_dsa_44|ml_dsa_65|sphincs_128f|sphincs_128s)", .{s});
}

fn parsePath(gpa: std.mem.Allocator, s: []const u8) []u32 {
    var list: std.ArrayList(u32) = .empty;
    if (s.len == 0) return list.toOwnedSlice(gpa) catch fail("oom", .{});
    var it = std.mem.splitScalar(u8, s, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const v = std.fmt.parseInt(u32, part, 10) catch fail("bad path component '{s}'", .{part});
        list.append(gpa, v) catch fail("oom", .{});
    }
    return list.toOwnedSlice(gpa) catch fail("oom", .{});
}

const Args = struct {
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    pairs: std.ArrayList(Pair) = .empty, // preserves repeated flags (--participant, --sig)
    fn get(self: Args, k: []const u8) ?[]const u8 {
        return self.map.get(k);
    }
    fn req(self: Args, k: []const u8) []const u8 {
        return self.map.get(k) orelse fail("--{s} required", .{k});
    }
};

fn parseU32(s: []const u8) u32 {
    return std.fmt.parseInt(u32, s, 10) catch fail("bad number '{s}'", .{s});
}

fn cmpShare(_: void, a: multisig.SignerShare, b: multisig.SignerShare) bool {
    return a.index < b.index;
}

pub fn main(init: std.process.Init) void {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next();
    const cmd = it.next() orelse fail("usage: vault <address|sign|verify> [flags]", .{});

    var args: Args = .{};
    while (it.next()) |a| {
        if (std.mem.startsWith(u8, a, "--")) {
            const key = a[2..];
            const val = it.next() orelse "";
            args.map.put(gpa, key, val) catch fail("oom", .{});
            args.pairs.append(gpa, .{ .key = key, .val = val }) catch fail("oom", .{});
        }
    }

    if (std.mem.eql(u8, cmd, "address")) {
        const master = hex32(args.req("seed"));
        const scheme = parseScheme(args.req("scheme"));
        const path = parsePath(gpa, args.get("path") orelse "");
        const id = signer.identity(gpa, master, scheme, path) catch |e| fail("derivation failed: {s}", .{@errorName(e)});
        out("scheme:  {s}", .{@tagName(scheme)});
        outHex(gpa, "pubkey", id.pubkey);
        outHex(gpa, "address", &id.address());
        return;
    }

    if (std.mem.eql(u8, cmd, "sign")) {
        const master = hex32(args.req("seed"));
        const scheme = parseScheme(args.req("scheme"));
        const path = parsePath(gpa, args.get("path") orelse "");
        const sighash = hex32(args.req("sighash"));
        const s = signer.sign(gpa, master, scheme, path, &sighash) catch |e| fail("signing failed: {s}", .{@errorName(e)});
        // Sanity: never emit a witness we can't verify ourselves.
        registry.verify(scheme, s.pubkey, &sighash, s.sig) catch fail("internal: produced signature does not verify", .{});
        out("scheme:  {s}", .{@tagName(scheme)});
        outHex(gpa, "pubkey", s.pubkey);
        outHex(gpa, "signature", s.sig);
        return;
    }

    if (std.mem.eql(u8, cmd, "verify")) {
        const scheme = parseScheme(args.req("scheme"));
        const pubkey = hexAlloc(gpa, args.req("pubkey"));
        const sighash = hex32(args.req("sighash"));
        const sig = hexAlloc(gpa, args.req("sig"));
        registry.verify(scheme, pubkey, &sighash, sig) catch |e| {
            out("INVALID: {s}", .{@errorName(e)});
            linux.exit(2);
        };
        out("VALID", .{});
        return;
    }

    // --- k-of-n multisig ---

    if (std.mem.eql(u8, cmd, "multisig-address")) {
        const threshold = parseU32(args.req("threshold"));
        var participants: std.ArrayList(multisig.Participant) = .empty;
        for (args.pairs.items) |p| {
            if (!std.mem.eql(u8, p.key, "participant")) continue;
            const ci = std.mem.indexOfScalar(u8, p.val, ':') orelse fail("--participant must be scheme:pubkeyhex", .{});
            participants.append(gpa, .{ .scheme = parseScheme(p.val[0..ci]), .pubkey = hexAlloc(gpa, p.val[ci + 1 ..]) }) catch fail("oom", .{});
        }
        if (participants.items.len == 0) fail("need at least one --participant scheme:pubkeyhex", .{});
        if (threshold < 1 or threshold > participants.items.len) fail("threshold must be 1..{d}", .{participants.items.len});
        const policy = multisig.encodePolicy(gpa, threshold, participants.items) catch fail("policy encoding failed", .{});
        out("threshold: {d}-of-{d}", .{ threshold, participants.items.len });
        outHex(gpa, "address", &multisig.commitment(policy));
        outHex(gpa, "policy", policy); // needed at spend time (goes in witness.pubkey)
        return;
    }

    if (std.mem.eql(u8, cmd, "multisig-combine")) {
        const policy = hexAlloc(gpa, args.req("policy"));
        const sighash = hex32(args.req("sighash"));
        var shares: std.ArrayList(multisig.SignerShare) = .empty;
        for (args.pairs.items) |p| {
            if (!std.mem.eql(u8, p.key, "sig")) continue;
            const ci = std.mem.indexOfScalar(u8, p.val, ':') orelse fail("--sig must be index:sighex", .{});
            shares.append(gpa, .{ .index = parseU32(p.val[0..ci]), .signature = hexAlloc(gpa, p.val[ci + 1 ..]) }) catch fail("oom", .{});
        }
        std.mem.sort(multisig.SignerShare, shares.items, {}, cmpShare);
        const signers = multisig.encodeSigners(gpa, shares.items) catch fail("signer encoding failed", .{});
        const commit = multisig.commitment(policy);
        multisig.verify(commit, policy, signers, sighash) catch |e| {
            out("INVALID: {s}", .{@errorName(e)});
            linux.exit(2);
        };
        out("VALID ({d} signatures)", .{shares.items.len});
        outHex(gpa, "address", &commit);
        // The spend witness: scheme = multisig (0x10), pubkey = policy, signature = signers.
        outHex(gpa, "witness_pubkey", policy);
        outHex(gpa, "witness_signature", signers);
        return;
    }

    fail("unknown command '{s}' (address|sign|verify|multisig-address|multisig-combine)", .{cmd});
}

fn hexAlloc(gpa: std.mem.Allocator, s: []const u8) []u8 {
    if (s.len % 2 != 0) fail("odd-length hex", .{});
    const b = gpa.alloc(u8, s.len / 2) catch fail("oom", .{});
    _ = std.fmt.hexToBytes(b, s) catch fail("bad hex", .{});
    return b;
}
