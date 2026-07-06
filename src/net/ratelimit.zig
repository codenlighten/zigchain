//! Per-peer token-bucket rate limiting.
//!
//! A peer on the open internet can flood a node with messages (inv/block/getaddr)
//! to waste CPU and bandwidth. Each peer gets a token bucket: it starts with a
//! burst allowance and regains one token every `refill_ms`. A message that finds
//! the bucket empty is refused, and the caller drops the connection.
//!
//! Time is passed in (`now_ms`) rather than read from a clock, so the policy is
//! deterministic and unit-testable.

const std = @import("std");

pub const RateLimiter = struct {
    burst: u32, // bucket capacity (max backlog of allowed messages)
    refill_ms: u32, // milliseconds to regain one token
    tokens: u32,
    last_ms: u64,

    pub fn init(burst: u32, refill_ms: u32, now_ms: u64) RateLimiter {
        std.debug.assert(burst >= 1 and refill_ms >= 1);
        return .{ .burst = burst, .refill_ms = refill_ms, .tokens = burst, .last_ms = now_ms };
    }

    /// Account for one message at `now_ms`; returns true if it is within budget.
    pub fn allow(self: *RateLimiter, now_ms: u64) bool {
        if (now_ms > self.last_ms) {
            const gained = (now_ms - self.last_ms) / self.refill_ms;
            if (gained > 0) {
                self.tokens = @intCast(@min(@as(u64, self.burst), @as(u64, self.tokens) + gained));
                self.last_ms += gained * self.refill_ms; // keep the fractional remainder
            }
        }
        if (self.tokens > 0) {
            self.tokens -= 1;
            return true;
        }
        return false;
    }
};

const testing = std.testing;

test "burst is allowed, then throttled until refill" {
    var rl = RateLimiter.init(5, 100, 1000);
    // Five immediate messages fit the burst.
    for (0..5) |_| try testing.expect(rl.allow(1000));
    // The sixth at the same instant is refused.
    try testing.expect(!rl.allow(1000));
    // After 100 ms, exactly one token is back.
    try testing.expect(rl.allow(1100));
    try testing.expect(!rl.allow(1100));
    // After 250 ms more, two tokens (not 2.5) are available.
    try testing.expect(rl.allow(1350));
    try testing.expect(rl.allow(1350));
    try testing.expect(!rl.allow(1350));
}

test "sustained rate at the refill cadence is allowed indefinitely" {
    var rl = RateLimiter.init(3, 50, 0);
    // Drain the burst.
    for (0..3) |_| try testing.expect(rl.allow(0));
    try testing.expect(!rl.allow(0));
    // One message every 50 ms is always allowed.
    var t: u64 = 50;
    while (t <= 5000) : (t += 50) try testing.expect(rl.allow(t));
}

test "tokens never exceed the burst even after a long idle" {
    var rl = RateLimiter.init(4, 10, 0);
    _ = rl.allow(0); // 3 left
    // Idle a long time — bucket refills only up to `burst`.
    var allowed: u32 = 0;
    while (rl.allow(1_000_000)) allowed += 1;
    try testing.expectEqual(@as(u32, 4), allowed);
}
