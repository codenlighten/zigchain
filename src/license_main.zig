//! SmartLedger license tool — issue and verify post-quantum software licenses.
//!
//!   zig build license -- keygen --seed <hex32>
//!   zig build license -- issue  --seed <hex32> --licensee "Acme" --tier enterprise \
//!                                --features vault,compliance --nodes 10 --days 365 \
//!                                --out acme.lic
//!   zig build license -- verify --in acme.lic --pubkey <hex>
//!
//! `keygen` prints the issuer public key to embed in the software; the issuer
//! keeps the seed secret. Licenses verify OFFLINE against the public key.

const std = @import("std");
const linux = std.os.linux;
const lic = @import("licensing/license.zig");
const codec = @import("core/serialization/codec.zig");
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    _ = linux.write(1, s.ptr, s.len);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    out("error: " ++ fmt, args);
    linux.exit(1);
}

fn nowSeconds() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

fn hexDecode(comptime n: usize, s: []const u8) ?[n]u8 {
    if (s.len != 2 * n) return null;
    var b: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, s) catch return null;
    return b;
}

fn writeFile(path: [*:0]const u8, data: []const u8) void {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(rc) != .SUCCESS) fail("cannot open {s} for writing", .{path});
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < data.len) {
        const w = linux.write(fd, data.ptr + off, data.len - off);
        if (linux.errno(w) != .SUCCESS or w == 0) fail("write failed", .{});
        off += w;
    }
}

fn readFile(gpa: std.mem.Allocator, path: [*:0]const u8) []u8 {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(rc) != .SUCCESS) fail("cannot open {s}", .{path});
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var list: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &buf) catch break;
        if (n == 0) break;
        list.appendSlice(gpa, buf[0..n]) catch fail("oom", .{});
    }
    return list.toOwnedSlice(gpa) catch fail("oom", .{});
}

const Args = struct {
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    fn get(self: Args, k: []const u8) ?[]const u8 {
        return self.map.get(k);
    }
    fn getOr(self: Args, k: []const u8, d: []const u8) []const u8 {
        return self.map.get(k) orelse d;
    }
};

fn parseFeatures(s: []const u8) u64 {
    var f: u64 = 0;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |name| {
        if (name.len == 0) continue;
        if (std.mem.eql(u8, name, "vault")) f |= lic.Feature.vault_scheme else if (std.mem.eql(u8, name, "compliance")) f |= lic.Feature.compliance_policy else if (std.mem.eql(u8, name, "high_capacity")) f |= lic.Feature.high_capacity else if (std.mem.eql(u8, name, "priority_support")) f |= lic.Feature.priority_support else fail("unknown feature '{s}'", .{name});
    }
    return f;
}

fn parseTier(s: []const u8) lic.Tier {
    if (std.mem.eql(u8, s, "community")) return .community;
    if (std.mem.eql(u8, s, "standard")) return .standard;
    if (std.mem.eql(u8, s, "enterprise")) return .enterprise;
    if (std.mem.eql(u8, s, "sovereign")) return .sovereign;
    fail("unknown tier '{s}' (community|standard|enterprise|sovereign)", .{s});
}

fn tierName(t: lic.Tier) []const u8 {
    return switch (t) {
        .community => "community",
        .standard => "standard",
        .enterprise => "enterprise",
        .sovereign => "sovereign",
        else => "unknown",
    };
}

pub fn main(init: std.process.Init) void {
    // A short-lived CLI: allocate from an arena freed on normal exit, so there
    // is no leak-tracking noise (error paths call exit() directly).
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // argv[0]

    const cmd = it.next() orelse fail("usage: license <keygen|issue|verify> [flags]", .{});

    var args: Args = .{};
    while (it.next()) |a| {
        if (std.mem.startsWith(u8, a, "--")) {
            const key = a[2..];
            const val = it.next() orelse "";
            args.map.put(gpa, key, val) catch fail("oom", .{});
        }
    }

    if (std.mem.eql(u8, cmd, "keygen")) {
        const seed = hexDecode(32, args.getOr("seed", "")) orelse fail("--seed <64 hex chars> required", .{});
        const kp = MlDsa44.KeyPair.generateDeterministic(seed) catch fail("keygen failed", .{});
        const pk = kp.public_key.toBytes();
        out("scheme:  ML-DSA-44", .{});
        out("issuer public key ({d} bytes) — embed this in the software:", .{pk.len});
        out("{s}", .{std.fmt.bytesToHex(pk, .lower)});
        return;
    }

    if (std.mem.eql(u8, cmd, "issue")) {
        const seed = hexDecode(32, args.getOr("seed", "")) orelse fail("--seed <64 hex chars> required", .{});
        const licensee = args.get("licensee") orelse fail("--licensee required", .{});
        if (licensee.len > lic.max_licensee_len) fail("licensee too long", .{});
        const kp = MlDsa44.KeyPair.generateDeterministic(seed) catch fail("bad seed", .{});

        const tier = parseTier(args.getOr("tier", "standard"));
        const features = parseFeatures(args.getOr("features", ""));
        const nodes = std.fmt.parseInt(u32, args.getOr("nodes", "0"), 10) catch fail("bad --nodes", .{});
        const tps = std.fmt.parseInt(u32, args.getOr("tps", "0"), 10) catch fail("bad --tps", .{});
        const days = std.fmt.parseInt(u64, args.getOr("days", "365"), 10) catch fail("bad --days", .{});
        const issued = nowSeconds();
        const expires: u64 = if (days == 0) 0 else issued + days * 86_400;

        // license id: from --id or derived from licensee+issued
        var id: [16]u8 = undefined;
        if (args.get("id")) |idhex| {
            id = hexDecode(16, idhex) orelse fail("--id must be 32 hex chars", .{});
        } else {
            const h = @import("core/crypto/hash.zig").hash(.license, licensee);
            @memcpy(&id, h[0..16]);
            std.mem.writeInt(u64, id[8..16], issued, .little);
        }

        const license = lic.License{
            .license_id = id,
            .licensee = licensee,
            .tier = tier,
            .features = features,
            .max_nodes = nodes,
            .max_tps = tps,
            .issued_at = issued,
            .expires_at = expires,
            .scheme = .ml_dsa_44,
        };
        const sig = lic.sign(gpa, kp, license) catch fail("signing failed", .{});
        defer gpa.free(sig);

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        var w = codec.Writer{ .list = &buf, .gpa = gpa };
        (lic.SignedLicense{ .license = license, .signature = sig }).encode(&w) catch fail("encode failed", .{});

        const path = args.getOr("out", "license.lic");
        const pathz = gpa.dupeZ(u8, path) catch fail("oom", .{});
        writeFile(pathz, buf.items);

        out("issued license -> {s} ({d} bytes)", .{ path, buf.items.len });
        out("  licensee: {s}", .{licensee});
        out("  tier:     {s}", .{tierName(tier)});
        out("  features: 0x{x}", .{features});
        out("  nodes:    {d} (0=unlimited)", .{nodes});
        out("  expires:  {d} (unix; 0=perpetual)", .{expires});
        out("  issuer pubkey: {s}", .{std.fmt.bytesToHex(kp.public_key.toBytes(), .lower)});
        return;
    }

    if (std.mem.eql(u8, cmd, "verify")) {
        const path = args.get("in") orelse fail("--in <file> required", .{});
        const pubhex = args.get("pubkey") orelse fail("--pubkey <hex> required", .{});
        const pubkey = gpa.alloc(u8, pubhex.len / 2) catch fail("oom", .{});
        defer gpa.free(pubkey);
        _ = std.fmt.hexToBytes(pubkey, pubhex) catch fail("bad --pubkey hex", .{});

        const pathz = gpa.dupeZ(u8, path) catch fail("oom", .{});
        const data = readFile(gpa, pathz);
        defer gpa.free(data);

        var r = codec.Reader{ .buf = data };
        const token = lic.SignedLicense.decode(&r, gpa) catch fail("malformed license file", .{});
        r.finish() catch fail("trailing bytes in license file", .{});

        const now = nowSeconds();
        lic.verify(gpa, pubkey, token.license, token.signature, now) catch |e| {
            out("INVALID: {s}", .{@errorName(e)});
            out("  licensee: {s}  tier: {s}", .{ token.license.licensee, tierName(token.license.tier) });
            linux.exit(2);
        };
        out("VALID", .{});
        out("  licensee: {s}", .{token.license.licensee});
        out("  tier:     {s}", .{tierName(token.license.tier)});
        out("  features: 0x{x}", .{token.license.features});
        out("  nodes:    {d}", .{token.license.max_nodes});
        out("  expires:  {d} (now={d})", .{ token.license.expires_at, now });
        return;
    }

    fail("unknown command '{s}' (keygen|issue|verify)", .{cmd});
}
