//! Peer-to-peer wire protocol: length-framed messages over a socket.
//!
//! Nodes gossip blocks with a tiny protocol — announce (inv), request
//! (get_block), deliver (block). The transport is built on raw Linux syscalls
//! (write / read / socketpair) so it stays independent of the 0.16 async-Io
//! rework, and the same `fd`-based functions work over a unix socketpair (used
//! by the deterministic tests) or a real TCP connection (used by node
//! processes). Every frame is a `u32` little-endian length followed by that many
//! bytes, so reads never span message boundaries.

const std = @import("std");
const linux = std.os.linux;
const hashmod = @import("../core/crypto/hash.zig");
const codec = @import("../core/serialization/codec.zig");
const blk = @import("../core/primitives/block.zig");

const Hash256 = hashmod.Hash256;

pub const max_frame: u32 = 32 * 1024 * 1024;

pub const Error = error{ WriteFailed, ReadFailed, Eof, BadFrame } || std.mem.Allocator.Error;

pub fn writeAll(fd: i32, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return Error.WriteFailed;
        off += rc;
    }
}

pub fn readExact(fd: i32, buf: []u8) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = std.posix.read(fd, buf[off..]) catch return Error.ReadFailed;
        if (n == 0) return Error.Eof;
        off += n;
    }
}

pub const Tag = enum(u8) { hello = 1, inv = 2, get_block = 3, block = 4 };

pub const Message = union(Tag) {
    hello: u32, // protocol version
    inv: Hash256, // "I have this block"
    get_block: Hash256, // "send me this block"
    block: []const u8, // an encoded block (references the receive buffer)
};

pub fn sendMessage(fd: i32, gpa: std.mem.Allocator, msg: Message) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    try payload.append(gpa, @intFromEnum(std.meta.activeTag(msg)));
    switch (msg) {
        .hello => |v| {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, v, .little);
            try payload.appendSlice(gpa, &b);
        },
        .inv, .get_block => |id| try payload.appendSlice(gpa, &id),
        .block => |bytes| try payload.appendSlice(gpa, bytes),
    }
    var lenb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenb, @intCast(payload.items.len), .little);
    try writeAll(fd, &lenb);
    try writeAll(fd, payload.items);
}

pub const Recv = struct {
    msg: Message,
    /// Backing buffer; free with the same allocator once `msg` is no longer used
    /// (a `.block` message references it).
    buffer: []u8,
};

pub fn recvMessage(fd: i32, gpa: std.mem.Allocator) Error!Recv {
    var lenb: [4]u8 = undefined;
    try readExact(fd, &lenb);
    const len = std.mem.readInt(u32, &lenb, .little);
    if (len < 1 or len > max_frame) return Error.BadFrame;
    const buf = try gpa.alloc(u8, len);
    errdefer gpa.free(buf);
    try readExact(fd, buf);

    const data = buf[1..];
    const msg: Message = switch (buf[0]) {
        1 => .{ .hello = if (data.len >= 4) std.mem.readInt(u32, data[0..4], .little) else 0 },
        2, 3 => msg: {
            if (data.len < 32) return Error.BadFrame;
            var id: Hash256 = undefined;
            @memcpy(&id, data[0..32]);
            break :msg if (buf[0] == 2) Message{ .inv = id } else Message{ .get_block = id };
        },
        4 => .{ .block = data },
        else => return Error.BadFrame,
    };
    return .{ .msg = msg, .buffer = buf };
}

// --- real TCP (for node processes across machines; shares the transport above) ---

pub const SocketError = error{ SocketFailed, BindFailed, ListenFailed, AcceptFailed, ConnectFailed, GetSockNameFailed };

/// Open a listening TCP socket on `port` (0 = ephemeral). Returns the fd.
pub fn tcpListen(port: u16) SocketError!i32 {
    const s = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (linux.errno(s) != .SUCCESS) return SocketError.SocketFailed;
    const fd: i32 = @intCast(s);
    var addr = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = 0 };
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return SocketError.BindFailed;
    if (linux.errno(linux.listen(fd, 16)) != .SUCCESS) return SocketError.ListenFailed;
    return fd;
}

/// The actual port a (possibly ephemeral) listener bound to.
pub fn boundPort(listener: i32) SocketError!u16 {
    var addr: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(listener, @ptrCast(&addr), &len)) != .SUCCESS) return SocketError.GetSockNameFailed;
    return std.mem.bigToNative(u16, addr.port);
}

pub fn tcpAccept(listener: i32) SocketError!i32 {
    const c = linux.accept(listener, null, null);
    if (linux.errno(c) != .SUCCESS) return SocketError.AcceptFailed;
    return @intCast(c);
}

/// Connect to an IPv4 peer. Returns a socket fd usable with send/recvMessage.
pub fn tcpConnect(ip: [4]u8, port: u16) SocketError!i32 {
    const s = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (linux.errno(s) != .SUCCESS) return SocketError.SocketFailed;
    const fd: i32 = @intCast(s);
    var addr = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(ip) };
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return SocketError.ConnectFailed;
    return fd;
}

/// Serialize a block to owned bytes for sending as a `.block` message.
pub fn encodeBlock(gpa: std.mem.Allocator, block: blk.Block) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try block.encode(&w);
    return list.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const chain = @import("../core/consensus/chain.zig");
const Block = blk.Block;

fn socketpair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketpairFailed;
    return fds;
}

test "oversized and empty frames are rejected (DoS guard)" {
    const gpa = testing.allocator;
    const fds = try socketpair();
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    // A hostile length prefix claiming more than max_frame must be refused
    // BEFORE any body is read, so a peer cannot force a huge allocation.
    var big: [4]u8 = undefined;
    std.mem.writeInt(u32, &big, max_frame + 1, .little);
    try writeAll(fds[0], &big);
    try testing.expectError(Error.BadFrame, recvMessage(fds[1], gpa));

    // A zero-length frame is also rejected.
    var zero: [4]u8 = undefined;
    std.mem.writeInt(u32, &zero, 0, .little);
    try writeAll(fds[0], &zero);
    try testing.expectError(Error.BadFrame, recvMessage(fds[1], gpa));
}

test "message framing round-trips over a real socket" {
    const gpa = testing.allocator;
    const fds = try socketpair();
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    const id = [_]u8{0xAB} ** 32;
    try sendMessage(fds[0], gpa, .{ .inv = id });
    const r = try recvMessage(fds[1], gpa);
    defer gpa.free(r.buffer);
    try testing.expect(r.msg == .inv);
    try testing.expectEqualSlices(u8, &id, &r.msg.inv);
}

test "gossip: a mined block propagates over a socket and both nodes converge" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = testing.allocator;

    const fds = try socketpair();
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    var a = chain.Chain.init(gpa, .{});
    defer a.deinit();
    var b = chain.Chain.init(gpa, .{});
    defer b.deinit();

    // Node A mines a block and holds it.
    const g = try chain.mineBlock(arena, &a, &.{}, 1000, &.{}, hashmod.zero);
    const gid = try a.acceptBlock(g);

    // A announces it; B, lacking it, requests it.
    try sendMessage(fds[0], gpa, .{ .inv = gid });
    const m_inv = try recvMessage(fds[1], gpa);
    defer gpa.free(m_inv.buffer);
    try testing.expect(m_inv.msg == .inv);
    try testing.expect(!b.dag.contains(m_inv.msg.inv));
    try sendMessage(fds[1], gpa, .{ .get_block = m_inv.msg.inv });

    // A receives the request and sends the block over the wire.
    const m_get = try recvMessage(fds[0], gpa);
    defer gpa.free(m_get.buffer);
    try testing.expect(m_get.msg == .get_block);
    const wire_bytes = try encodeBlock(gpa, g);
    defer gpa.free(wire_bytes);
    try sendMessage(fds[0], gpa, .{ .block = wire_bytes });

    // B receives the block, decodes it off the wire, and accepts it.
    const m_blk = try recvMessage(fds[1], gpa);
    defer gpa.free(m_blk.buffer);
    try testing.expect(m_blk.msg == .block);
    var reader = codec.Reader{ .buf = m_blk.msg.block };
    const decoded = try Block.decode(&reader, arena);
    _ = try b.acceptBlock(decoded);

    // Both nodes converged — over a real socket, from a serialized block.
    try testing.expectEqualSlices(u8, &a.tip().?, &b.tip().?);
    try testing.expectEqualSlices(u8, &(try a.utxoCommitment()), &(try b.utxoCommitment()));
}

fn tcpAcceptRecv(listener: i32, out: *[32]u8, done: *std.atomic.Value(bool)) void {
    const c = tcpAccept(listener) catch return;
    defer _ = linux.close(c);
    const r = recvMessage(c, std.heap.page_allocator) catch return;
    defer std.heap.page_allocator.free(r.buffer);
    if (r.msg == .inv) out.* = r.msg.inv;
    done.store(true, .release);
}

test "real TCP loopback: connect, send a message, receive it" {
    const l = try tcpListen(0); // ephemeral port
    defer _ = linux.close(l);
    const port = try boundPort(l);

    var received: [32]u8 = [_]u8{0} ** 32;
    var done = std.atomic.Value(bool).init(false);
    const th = try std.Thread.spawn(.{}, tcpAcceptRecv, .{ l, &received, &done });

    const c = try tcpConnect(.{ 127, 0, 0, 1 }, port);
    defer _ = linux.close(c);
    const id = [_]u8{0x5A} ** 32;
    try sendMessage(c, testing.allocator, .{ .inv = id });
    th.join();

    try testing.expect(done.load(.acquire));
    try testing.expectEqualSlices(u8, &id, &received);
}
