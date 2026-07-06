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

    /// A unicast IPv4 we'd be willing to dial. Rejects the wildcard, link-local,
    /// broadcast, and multicast/reserved ranges so a peer (or a failed
    /// getpeername returning 0.0.0.0) cannot poison the book. Loopback is allowed
    /// so local testnets work; connecting to our own node is caught separately by
    /// the hello nonce.
    pub fn routable(ip: [4]u8) bool {
        if (ip[0] == 0) return false; // 0.0.0.0/8 (incl. the getpeername-failure sentinel)
        if (ip[0] == 169 and ip[1] == 254) return false; // link-local
        if (ip[0] >= 224) return false; // multicast (224+), reserved (240+), 255.255.255.255
        return true;
    }

    /// Record a peer address. Returns true if it was newly added. Ignores our own
    /// address, duplicates, unroutable addresses, and anything past the cap.
    pub fn add(self: *AddressBook, a: NetAddr) bool {
        if (a.port == 0) return false;
        if (!routable(a.ip)) return false;
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

test "unroutable addresses are rejected (0.0.0.0 poison, link-local, broadcast, multicast)" {
    var book = AddressBook.init(testing.allocator, .{ .ip = .{ 10, 0, 0, 1 }, .port = 9000 }, 100);
    defer book.deinit();
    try testing.expect(!book.add(.{ .ip = .{ 0, 0, 0, 0 }, .port = 9001 })); // getpeername failure
    try testing.expect(!book.add(.{ .ip = .{ 169, 254, 1, 1 }, .port = 9001 })); // link-local
    try testing.expect(!book.add(.{ .ip = .{ 255, 255, 255, 255 }, .port = 9001 })); // broadcast
    try testing.expect(!book.add(.{ .ip = .{ 224, 0, 0, 1 }, .port = 9001 })); // multicast
    // Loopback and routable unicast are accepted.
    try testing.expect(book.add(.{ .ip = .{ 127, 0, 0, 1 }, .port = 9001 }));
    try testing.expect(book.add(.{ .ip = .{ 203, 0, 113, 5 }, .port = 9001 }));
    try testing.expectEqual(@as(usize, 2), book.items().len);
}
