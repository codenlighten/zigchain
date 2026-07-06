//! `zig build vectors -- <scenarios.json>` — emits the canonical differential
//! report for the Zig implementation. The Rust `vectors` binary emits the exact
//! same report for the same input; `tools/difftest.sh` diffs the two. Any
//! difference is a consensus divergence between the two implementations.
//!
//! Uses std.posix directly for file/stdout I/O to stay independent of the
//! 0.16 async-Io rework.

const std = @import("std");
const hashmod = @import("core/crypto/hash.zig");
const prim = @import("core/primitives/types.zig");
const pq = @import("core/crypto/pq/registry.zig");
const blk = @import("core/primitives/block.zig");
const massmod = @import("core/consensus/mass.zig");
const finality = @import("core/consensus/finality.zig");
const Dag = @import("core/consensus/dag.zig").Dag;
const Ghostdag = @import("core/consensus/ghostdag.zig").Ghostdag;

const Hash256 = hashmod.Hash256;
const Value = std.json.Value;

fn idOf(i: u32) Hash256 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, i, .little);
    return hashmod.hash(.block_header, &b);
}

fn hexToBytes(gpa: std.mem.Allocator, s: []const u8) []u8 {
    const n = s.len / 2;
    const buf = gpa.alloc(u8, n) catch unreachable;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        buf[i] = std.fmt.parseInt(u8, s[2 * i .. 2 * i + 2], 16) catch unreachable;
    }
    return buf;
}

fn h32(gpa: std.mem.Allocator, s: []const u8) Hash256 {
    const b = hexToBytes(gpa, s);
    var out: Hash256 = undefined;
    @memcpy(&out, b[0..32]);
    return out;
}

fn field(v: Value, name: []const u8) Value {
    return v.object.get(name).?;
}
fn intOf(v: Value) i64 {
    return v.integer;
}

const Out = struct {
    buf: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    fn line(self: Out, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.allocPrint(self.gpa, fmt, args) catch unreachable;
        self.buf.appendSlice(self.gpa, s) catch unreachable;
    }
};

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // Fixed shared input (run from the repo root). Both the Zig and Rust
    // `vectors` tools read this same file.
    // Embed the shared scenarios at compile time — avoids the 0.16 async-Io
    // file API and guarantees both tools consume byte-identical input.
    const raw = @embedFile("scenarios_json");
    const parsed = try std.json.parseFromSlice(Value, gpa, raw, .{});
    const root = parsed.value;

    var buf: std.ArrayList(u8) = .empty;
    const out = Out{ .buf = &buf, .gpa = gpa };

    // --- transaction vectors ---
    if (root.object.get("tx_vectors")) |txs| {
        for (txs.array.items, 0..) |tv, i| {
            const inputs_j = field(tv, "inputs").array.items;
            const outputs_j = field(tv, "outputs").array.items;
            const witnesses_j = field(tv, "witnesses").array.items;

            const inputs = gpa.alloc(prim.Input, inputs_j.len) catch unreachable;
            for (inputs_j, 0..) |inj, k| {
                inputs[k] = .{ .outpoint = .{
                    .txid = h32(gpa, field(inj, "txid").string),
                    .index = @intCast(intOf(field(inj, "index"))),
                } };
            }
            const outputs = gpa.alloc(prim.Output, outputs_j.len) catch unreachable;
            for (outputs_j, 0..) |ouj, k| {
                outputs[k] = .{
                    .value = @intCast(intOf(field(ouj, "value"))),
                    .scheme = @enumFromInt(@as(u8, @intCast(intOf(field(ouj, "scheme"))))),
                    .commitment = h32(gpa, field(ouj, "commitment").string),
                };
            }
            const wits = gpa.alloc(prim.Witness, witnesses_j.len) catch unreachable;
            for (witnesses_j, 0..) |wj, k| {
                wits[k] = .{
                    .scheme = @enumFromInt(@as(u8, @intCast(intOf(field(wj, "scheme"))))),
                    .pubkey = hexToBytes(gpa, field(wj, "pubkey").string),
                    .signature = hexToBytes(gpa, field(wj, "signature").string),
                };
            }

            const tx = prim.Transaction{
                .version = @intCast(intOf(field(tv, "version"))),
                .inputs = inputs,
                .outputs = outputs,
                .witnesses = wits,
                .payload = hexToBytes(gpa, field(tv, "payload").string),
            };
            const scheme: pq.SchemeTag = @enumFromInt(@as(u8, @intCast(intOf(field(tv, "sighash_scheme")))));

            out.line("tx {d} txid {s}\n", .{ i, std.fmt.bytesToHex(try tx.txid(gpa), .lower) });
            out.line("tx {d} wtxid {s}\n", .{ i, std.fmt.bytesToHex(try tx.wtxid(gpa), .lower) });
            out.line("tx {d} sighash {s}\n", .{ i, std.fmt.bytesToHex(try tx.sighash(gpa, scheme), .lower) });
            out.line("tx {d} mass {d}\n", .{ i, try massmod.txMass(gpa, tx) });
        }
    }

    // --- finality vote messages ---
    if (root.object.get("finality_vectors")) |fvs| {
        for (fvs.array.items, 0..) |fv, i| {
            const cut = finality.Cut{
                .block = h32(gpa, field(fv, "block").string),
                .blue_score = @intCast(intOf(field(fv, "blue_score"))),
            };
            out.line("finality {d} vote {s}\n", .{ i, std.fmt.bytesToHex(finality.voteMessage(cut), .lower) });
        }
    }

    // --- address commitments ---
    if (root.object.get("address_vectors")) |avs| {
        for (avs.array.items, 0..) |av, i| {
            const scheme: pq.SchemeTag = @enumFromInt(@as(u8, @intCast(intOf(field(av, "scheme")))));
            const pk = hexToBytes(gpa, field(av, "pubkey").string);
            const c = prim.addressCommitment(scheme, pk);
            out.line("addr {d} {s}\n", .{ i, std.fmt.bytesToHex(c, .lower) });
        }
    }

    // --- merkle roots ---
    if (root.object.get("merkle_vectors")) |mvs| {
        for (mvs.array.items, 0..) |mv, i| {
            const leaves_j = field(mv, "leaves").array.items;
            const leaves = gpa.alloc(Hash256, leaves_j.len) catch unreachable;
            for (leaves_j, 0..) |lj, k| leaves[k] = h32(gpa, lj.string);
            const r = try blk.merkleRoot(gpa, leaves);
            out.line("merkle {d} {s}\n", .{ i, std.fmt.bytesToHex(r, .lower) });
        }
    }

    // --- GHOSTDAG scenarios ---
    if (root.object.get("dag_scenarios")) |dss| {
        for (dss.array.items) |ds| {
            const name = field(ds, "name").string;
            const k: u32 = @intCast(intOf(field(ds, "k")));
            const blocks_j = field(ds, "blocks").array.items;

            var dag = Dag.init(gpa);
            var rev: std.AutoHashMapUnmanaged(Hash256, u32) = .empty;
            for (blocks_j) |bj| {
                const id: u32 = @intCast(intOf(field(bj, "id")));
                const parents_j = field(bj, "parents").array.items;
                const ps = gpa.alloc(Hash256, parents_j.len) catch unreachable;
                for (parents_j, 0..) |pj, k2| ps[k2] = idOf(@intCast(intOf(pj)));
                try dag.addBlock(idOf(id), ps);
                try rev.put(gpa, idOf(id), id);
            }

            var gd = Ghostdag.init(gpa, &dag, k);
            try gd.compute();

            // blue scores, ascending id (blocks are listed ascending)
            for (blocks_j) |bj| {
                const id: u32 = @intCast(intOf(field(bj, "id")));
                out.line("dag {s} blue {d}:{d}\n", .{ name, id, gd.get(idOf(id)).?.blue_score });
            }
            out.line("dag {s} tip {d}\n", .{ name, rev.get(gd.selectedTip().?).? });

            const order = try gd.order(gpa);
            out.line("dag {s} order ", .{name});
            for (order, 0..) |oid, j| {
                if (j != 0) out.line(",", .{});
                out.line("{d}", .{rev.get(oid).?});
            }
            out.line("\n", .{});
        }
    }

    // Emit the report (stderr via std.debug.print; the difftest captures it).
    std.debug.print("{s}", .{buf.items});
}
