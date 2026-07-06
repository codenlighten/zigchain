//! Persistent block store — an append-only log so a node survives restart.
//!
//! Every accepted block is appended as `[u32 length][block bytes]`. On startup
//! the log is replayed in order (which is a valid topological order, since a
//! block is only accepted after its parents), rebuilding the whole chain by
//! re-validating each block. A trailing record left half-written by a crash is
//! detected and ignored, so replay is crash-safe. Built on raw Linux file
//! syscalls to stay independent of the 0.16 async-Io rework.

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{ OpenFailed, WriteFailed } || std.mem.Allocator.Error;

fn writeAll(fd: i32, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return Error.WriteFailed;
        off += rc;
    }
}

/// Read up to buf.len bytes; returns how many were read (short = EOF reached).
fn readCount(fd: i32, buf: []u8) usize {
    var off: usize = 0;
    while (off < buf.len) {
        const n = std.posix.read(fd, buf[off..]) catch break;
        if (n == 0) break;
        off += n;
    }
    return off;
}

pub const BlockStore = struct {
    fd: i32,

    pub fn open(path: [*:0]const u8) Error!BlockStore {
        const rc = linux.openat(linux.AT.FDCWD, path, .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .APPEND = true,
        }, 0o644);
        if (linux.errno(rc) != .SUCCESS) return Error.OpenFailed;
        return .{ .fd = @intCast(rc) };
    }

    pub fn close(self: *BlockStore) void {
        _ = linux.close(self.fd);
    }

    pub fn append(self: *BlockStore, bytes: []const u8) Error!void {
        var lenb: [4]u8 = undefined;
        std.mem.writeInt(u32, &lenb, @intCast(bytes.len), .little);
        try writeAll(self.fd, &lenb);
        try writeAll(self.fd, bytes);
    }

    /// Flush to stable storage (call at shutdown or after critical writes).
    pub fn sync(self: *BlockStore) void {
        _ = linux.fsync(self.fd);
    }

    /// Replay each stored record from the start, invoking `f(ctx, bytes)`.
    /// `bytes` is only valid during the call. Returns the record count. A
    /// truncated trailing record is silently ignored (crash safety).
    pub fn replay(self: *BlockStore, gpa: std.mem.Allocator, ctx: anytype, comptime f: anytype) Error!usize {
        _ = linux.lseek(self.fd, 0, 0); // SEEK_SET
        var count: usize = 0;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        while (true) {
            var lenb: [4]u8 = undefined;
            const got = readCount(self.fd, &lenb);
            if (got == 0) break; // clean end of log
            if (got != 4) break; // truncated length prefix
            const len = std.mem.readInt(u32, &lenb, .little);
            try buf.resize(gpa, len);
            if (readCount(self.fd, buf.items) != len) break; // truncated record
            f(ctx, buf.items);
            count += 1;
        }
        _ = linux.lseek(self.fd, 0, 2); // SEEK_END — future appends go to the end
        return count;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const Collector = struct {
    gpa: std.mem.Allocator,
    items: std.ArrayList([]u8) = .empty,
    fn cb(self: *Collector, bytes: []const u8) void {
        const owned = self.gpa.dupe(u8, bytes) catch return;
        self.items.append(self.gpa, owned) catch {};
    }
};

test "block store: append then replay round-trips, survives reopen" {
    const gpa = testing.allocator;
    const path = "/tmp/zc_store_test.log";
    _ = linux.unlink(path); // clean slate

    // Write three records, then close (simulating a running node).
    {
        var s = try BlockStore.open(path);
        try s.append("first");
        try s.append("second-record");
        try s.append("third!");
        s.sync();
        s.close();
    }

    // Reopen and replay — the data must come back intact and in order.
    var s2 = try BlockStore.open(path);
    defer s2.close();
    var c = Collector{ .gpa = gpa };
    defer {
        for (c.items.items) |it| gpa.free(it);
        c.items.deinit(gpa);
    }
    const n = try s2.replay(gpa, &c, Collector.cb);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("first", c.items.items[0]);
    try testing.expectEqualStrings("second-record", c.items.items[1]);
    try testing.expectEqualStrings("third!", c.items.items[2]);

    _ = linux.unlink(path);
}
