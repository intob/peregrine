const std = @import("std");

pub fn Queue(comptime T: type) type {
    return struct {
        const Node = struct { data: T, next: ?*Node };
        mutex: std.Thread.Mutex,
        head: ?*Node,
        tail: ?*Node,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) !*Queue(T) {
            const queue = try allocator.create(Queue(T));
            queue.* = .{
                .mutex = std.Thread.Mutex{},
                .head = null,
                .tail = null,
                .allocator = allocator,
            };
            return queue;
        }

        pub fn deinit(self: *Queue(T)) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (self.head) |node| {
                const next = node.next;
                self.allocator.destroy(node);
                self.head = next;
            }
            self.tail = null;
        }

        pub fn write(self: *Queue(T), data: T) !void {
            const new_node = try self.allocator.create(Node);
            new_node.* = .{
                .data = data,
                .next = null,
            };
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.tail) |tail| {
                tail.next = new_node;
                self.tail = new_node;
            } else {
                self.head = new_node;
                self.tail = new_node;
            }
        }

        pub fn read(self: *Queue(T)) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.head) |node| {
                const data = node.data;
                self.head = node.next;
                if (self.head == null) {
                    self.tail = null;
                }
                self.allocator.destroy(node);
                return data;
            }
            return null;
        }
    };
}

test "basic usage" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const queue = try Queue(u8).init(allocator);
    var r = queue.read();
    try std.testing.expect(r == null);
    try queue.write(1);
    try queue.write(2);
    try queue.write(3);
    try queue.write(4);
    try queue.write(5);
    r = queue.read();
    try std.testing.expect(r == 1);
    r = queue.read();
    try std.testing.expect(r == 2);
    r = queue.read();
    try std.testing.expect(r == 3);
    r = queue.read();
    try std.testing.expect(r == 4);
    r = queue.read();
    try std.testing.expect(r == 5);
    r = queue.read();
    try std.testing.expect(r == null);
    try queue.write(6);
    r = queue.read();
    try std.testing.expect(r == 6);
}
