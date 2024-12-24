const std = @import("std");

pub fn RingBuffer(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        data: []T,
        w_head: usize,
        r_head: usize,
        full: bool,

        const Self = @This();
        pub const Error = error{
            NotEnoughData,
            BufferFull,
        };

        pub fn init(allocator: std.mem.Allocator, size: usize) !*Self {
            const r = try allocator.create(Self);
            r.* = .{
                .allocator = allocator,
                .data = try allocator.alloc(T, size),
                .w_head = 0,
                .r_head = 0,
                .full = false,
            };
            return r;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.data);
            self.allocator.destroy(self);
        }

        pub fn write(self: *Self, data: []const T) Error!void {
            const av = self.available();
            if (av < data.len) {
                return error.BufferFull;
            }

            for (data) |d| {
                self.data[self.w_head] = d;
                self.w_head = (self.w_head + 1) % self.data.len;
                if (self.w_head == self.r_head) self.full = true;
            }
        }

        pub fn read(self: *Self, buf: []T) Error!void {
            if (self.len() < buf.len) {
                return error.NotEnoughData;
            }

            for (buf, 0..) |*d, i| {
                d.* = self.data[(self.r_head + i) % self.data.len];
            }
            self.r_head = (self.r_head + buf.len) % self.data.len;
            self.full = false;
        }

        pub fn len(self: *Self) usize {
            if (self.full) return self.data.len;
            return if (self.w_head >= self.r_head)
                self.w_head - self.r_head
            else
                self.data.len - (self.r_head - self.w_head);
        }

        pub fn available(self: *Self) usize {
            return self.data.len - self.len();
        }

        pub fn isEmpty(self: *Self) bool {
            return self.len() == 0;
        }

        pub fn clear(self: *Self) void {
            self.r_head = 0;
            self.w_head = 0;
            self.full = false;
        }
    };
}

test "write full" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    const ring = try RingBuffer(u8).init(alloc, 5);
    defer ring.deinit();

    try std.testing.expect(ring.len() == 0);

    var buf: [5]u8 = undefined;
    try std.testing.expectError(error.NotEnoughData, ring.read(&buf));

    try ring.write("Hello"[0..]);
    try std.testing.expectEqual(5, ring.len());
    try std.testing.expect(ring.full);

    try std.testing.expectError(error.BufferFull, ring.write("Test"[0..]));

    try ring.read(&buf);
    try std.testing.expectEqualSlices(u8, "Hello", &buf);
    try std.testing.expect(ring.len() == 0);
}
