//! Canonical, byte-exact serialization.
//!
//! Determinism rules for consensus:
//!  - All integers are fixed-width little-endian. No `usize` on the wire
//!    (its width differs across 32/64-bit targets → consensus split).
//!  - Collection counts are `u32` (not a variable-length integer) so there is
//!    exactly one valid encoding of every value — no canonicalisation traps.
//!  - Variable-length byte fields are length-prefixed with a `u32` and bounded
//!    on decode so a hostile encoding cannot force an unbounded allocation.

const std = @import("std");
const Hash256 = @import("../crypto/hash.zig").Hash256;

pub const Writer = struct {
    list: *std.ArrayList(u8),
    gpa: std.mem.Allocator,

    pub fn writeByte(self: *Writer, v: u8) !void {
        try self.list.append(self.gpa, v);
    }
    pub fn writeU32(self: *Writer, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.list.appendSlice(self.gpa, &b);
    }
    pub fn writeU64(self: *Writer, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try self.list.appendSlice(self.gpa, &b);
    }
    pub fn writeBytes(self: *Writer, s: []const u8) !void {
        try self.list.appendSlice(self.gpa, s);
    }
    pub fn writeHash(self: *Writer, h: Hash256) !void {
        try self.list.appendSlice(self.gpa, &h);
    }
    /// u32 length-prefixed variable bytes (public keys, signatures).
    pub fn writeVarBytes(self: *Writer, s: []const u8) !void {
        try self.writeU32(@intCast(s.len));
        try self.writeBytes(s);
    }
};

pub const ReadError = error{ UnexpectedEof, TooLarge, TrailingBytes };

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, n: usize) ReadError![]const u8 {
        if (self.buf.len - self.pos < n) return ReadError.UnexpectedEof;
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    pub fn readByte(self: *Reader) ReadError!u8 {
        return (try self.take(1))[0];
    }
    pub fn readU32(self: *Reader) ReadError!u32 {
        const s = try self.take(4);
        return std.mem.readInt(u32, s[0..4], .little);
    }
    pub fn readU64(self: *Reader) ReadError!u64 {
        const s = try self.take(8);
        return std.mem.readInt(u64, s[0..8], .little);
    }
    pub fn readHash(self: *Reader) ReadError!Hash256 {
        const s = try self.take(32);
        var h: Hash256 = undefined;
        @memcpy(&h, s);
        return h;
    }

    /// Read exactly `n` raw bytes, returning a slice into the buffer (no copy).
    pub fn readN(self: *Reader, n: usize) ReadError![]const u8 {
        return self.take(n);
    }
    /// Returns a slice into the underlying buffer (no copy). Bounded by `max`.
    pub fn readVarBytes(self: *Reader, max: u32) ReadError![]const u8 {
        const n = try self.readU32();
        if (n > max) return ReadError.TooLarge;
        return self.take(n);
    }
    pub fn atEnd(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }
    /// Assert the whole buffer was consumed — canonical decoders reject trailers.
    pub fn finish(self: *const Reader) ReadError!void {
        if (!self.atEnd()) return ReadError.TrailingBytes;
    }
};

const testing = std.testing;

test "round-trip primitives, little-endian, exact consumption" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var w = Writer{ .list = &list, .gpa = testing.allocator };

    try w.writeByte(0xAB);
    try w.writeU32(0x11223344);
    try w.writeU64(0xDEADBEEFCAFEF00D);
    try w.writeVarBytes("hello");

    var r = Reader{ .buf = list.items };
    try testing.expectEqual(@as(u8, 0xAB), try r.readByte());
    try testing.expectEqual(@as(u32, 0x11223344), try r.readU32());
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFEF00D), try r.readU64());
    try testing.expectEqualStrings("hello", try r.readVarBytes(16));
    try r.finish();
}

test "little-endian byte order is fixed" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var w = Writer{ .list = &list, .gpa = testing.allocator };
    try w.writeU32(1);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0 }, list.items);
}

test "hostile length is bounded, truncation is caught" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var w = Writer{ .list = &list, .gpa = testing.allocator };
    try w.writeVarBytes("abcd");

    var r1 = Reader{ .buf = list.items };
    try testing.expectError(ReadError.TooLarge, r1.readVarBytes(2));

    var r2 = Reader{ .buf = list.items[0..3] }; // claims 4 bytes, only 3 present
    try testing.expectError(ReadError.UnexpectedEof, r2.readVarBytes(64));
}
