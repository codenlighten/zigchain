//! A bounded book of known peer addresses, fed by peer exchange (PEX).
//!
//! A node learns addresses from every peer's `hello` (which advertises its listen
//! port) and from `addr` replies to `getaddr`. The book dedups, refuses its own
//! address, and is capped so a peer cannot make it grow without bound. A
//! discovery loop dials entries that are not yet connected, up to the peer cap.

const std = @import("std");
const wire = @import("wire.zig");

pub const NetAddr = wire.NetAddr;

pub const AddressBook = struct {
    gpa: std.mem.Allocator,
    self_addr: NetAddr, // never store or dial ourselves
    cap: usize,
    addrs: std.ArrayList(NetAddr) = .empty,

    pub fn init(gpa: std.mem.Allocator, self_addr: NetAddr, cap: usize) AddressBook {
        return .{ .gpa = gpa, .self_addr = self_addr, .cap = cap };
    }
    pub fn deinit(self: *AddressBook) void {
        self.addrs.deinit(self.gpa);
    }

    pub fn contains(self: *const AddressBook, a: NetAddr) bool {
        for (self.addrs.items) |x| if (x.eql(a)) return true;
        return false;
    }

    /// Record a peer address. Returns true if it was newly added. Ignores our own
    /// address, duplicates, and anything past the cap.
    pub fn add(self: *AddressBook, a: NetAddr) bool {
        if (a.port == 0) return false;
        if (a.eql(self.self_addr)) return false;
        if (self.contains(a)) return false;
        if (self.addrs.items.len >= self.cap) return false;
        self.addrs.append(self.gpa, a) catch return false;
        return true;
    }

    pub fn items(self: *const AddressBook) []const NetAddr {
        return self.addrs.items;
    }
};

const testing = std.testing;

test "address book dedups, refuses self, and caps" {
    const self_addr = NetAddr{ .ip = .{ 127, 0, 0, 1 }, .port = 9000 };
    var book = AddressBook.init(testing.allocator, self_addr, 3);
    defer book.deinit();

    const a = NetAddr{ .ip = .{ 127, 0, 0, 1 }, .port = 9001 };
    try testing.expect(book.add(a)); // new
    try testing.expect(!book.add(a)); // duplicate
    try testing.expect(!book.add(self_addr)); // our own address
    try testing.expect(!book.add(.{ .ip = .{ 1, 2, 3, 4 }, .port = 0 })); // port 0 is invalid

    try testing.expect(book.add(.{ .ip = .{ 127, 0, 0, 1 }, .port = 9002 }));
    try testing.expect(book.add(.{ .ip = .{ 127, 0, 0, 1 }, .port = 9003 }));
    // Cap of 3 reached.
    try testing.expect(!book.add(.{ .ip = .{ 127, 0, 0, 1 }, .port = 9004 }));
    try testing.expectEqual(@as(usize, 3), book.items().len);
    try testing.expect(book.contains(a));
}
