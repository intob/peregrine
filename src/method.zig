const std = @import("std");
const testing = std.testing;

pub const Method = enum(u4) {
    GET,
    PUT,
    HEAD,
    POST,
    PATCH,
    TRACE,
    DELETE,
    CONNECT,
    OPTIONS,

    const MethodMask = struct {
        name: []const u8,
        variant: Method,
    };

    const method_masks = blk: {
        const masks = [_]MethodMask{
            .{ .name = "GET", .variant = .GET },
            .{ .name = "PUT", .variant = .PUT },
            .{ .name = "HEAD", .variant = .HEAD },
            .{ .name = "POST", .variant = .POST },
            .{ .name = "PATCH", .variant = .PATCH },
            .{ .name = "TRACE", .variant = .TRACE },
            .{ .name = "DELETE", .variant = .DELETE },
            .{ .name = "CONNECT", .variant = .CONNECT },
            .{ .name = "OPTIONS", .variant = .OPTIONS },
        };

        var result: [masks.len]@Vector(8, u8) = undefined;
        for (masks, 0..) |mask, i| {
            var vec: @Vector(8, u8) = @splat(' ');
            for (mask.name, 0..) |c, j| {
                if (j >= 8) break;
                vec[j] = c;
            }
            result[i] = vec;
        }
        break :blk result;
    };

    /// Parses the method from any 8-byte input.
    pub fn parse(bytes: []const u8) !Method {
        // Find the first space
        const method_end = for (bytes, 0..) |b, i| {
            if (b == ' ') break i;
        } else bytes.len;
        // Create vector of input bytes padded with spaces
        var method_bytes: @Vector(8, u8) = @splat(' ');
        @memcpy(@as([*]u8, @ptrCast(&method_bytes))[0..@min(method_end, 8)], bytes[0..@min(method_end, 8)]);
        // Lookup method
        inline for (method_masks, std.meta.tags(Method)) |mask, variant| {
            if (@reduce(.And, method_bytes == mask)) {
                return variant;
            }
        }
        return error.UnsupportedMethod;
    }

    pub fn toLength(self: Method) usize {
        return switch (self) {
            .GET => 3,
            .PUT => 3,
            .HEAD => 4,
            .POST => 4,
            .PATCH => 5,
            .TRACE => 5,
            .DELETE => 6,
            .CONNECT => 7,
            .OPTIONS => 7,
        };
    }
};

test "parse valid HTTP methods" {
    try testing.expectEqual(Method.GET, try Method.parse("GET "));
    try testing.expectEqual(Method.PUT, try Method.parse("PUT /som"));
    try testing.expectEqual(Method.HEAD, try Method.parse("HEAD"));
    try testing.expectEqual(Method.POST, try Method.parse("POST"));
    try testing.expectEqual(Method.PATCH, try Method.parse("PATCH"));
    try testing.expectEqual(Method.TRACE, try Method.parse("TRACE"));
    try testing.expectEqual(Method.DELETE, try Method.parse("DELETE"));
    try testing.expectEqual(Method.CONNECT, try Method.parse("CONNECT"));
    try testing.expectEqual(Method.OPTIONS, try Method.parse("OPTIONS"));
}

test "parse invalid HTTP methods" {
    try testing.expectError(error.UnsupportedMethod, Method.parse(""));
    try testing.expectError(error.UnsupportedMethod, Method.parse("INVALID"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("POSTING"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("get"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("Get"));
    //try testing.expectError(error.InvalidMethod, Method.parse("GET "));
}

test "parse methods with matching length but invalid content" {
    try testing.expectError(error.UnsupportedMethod, Method.parse("GXT"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("PXT"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("HXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("PXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("PXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("TXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("DXXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("CXXXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("OXXXXXX"));
}

test "parse methods with special characters" {
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET\t"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET\n"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET\r"));
}

fn benchmark(method: []const u8) !void {
    const iterations: usize = 100_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        const h = try Method.parse(method);
        std.mem.doNotOptimizeAway(h);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time to parse \"{s}\": {d}ns\n", .{ method, avg_ns });
}

test "benchmark parse GET" {
    try benchmark("GET");
}

test "benchmark parse POST" {
    try benchmark("POST");
}

test "benchmark parse PATCH" {
    try benchmark("PATCH");
}

test "benchmark parse DELETE" {
    try benchmark("DELETE");
}

test "benchmark parse OPTIONS" {
    try benchmark("OPTIONS");
}

// In isolation, this parser is faster, but requires that we know the length of the method.
// In practice, finding the first ' ', and using this parser is slower than the version
// above. The version above uses vectors to find the first space, and matches against
// the comptime-generated lookup table.
pub fn parseFaterButSlowerInPractice(bytes: []const u8) !Method {
    return switch (bytes.len) {
        3 => switch (bytes[0]) {
            'G' => if (bytes[1] == 'E' and bytes[2] == 'T')
                Method.GET
            else
                error.UnsupportedMethod,
            'P' => if (bytes[1] == 'U' and bytes[2] == 'T')
                Method.PUT
            else
                error.UnsupportedMethod,
            else => error.UnsupportedMethod,
        },
        4 => switch (bytes[0]) {
            'H' => if (bytes[1] == 'E' and bytes[2] == 'A' and bytes[3] == 'D')
                Method.HEAD
            else
                error.UnsupportedMethod,
            'P' => if (bytes[1] == 'O' and bytes[2] == 'S' and bytes[3] == 'T')
                Method.POST
            else
                error.UnsupportedMethod,
            else => error.UnsupportedMethod,
        },
        5 => switch (bytes[0]) {
            // Skip checking C because both PATCH and TRACE have 'C' at index 3.
            // This is arguably not worth the improvement of ~1ns.
            'P' => if (bytes[1] == 'A' and bytes[2] == 'T' and bytes[4] == 'H')
                Method.PATCH
            else
                error.UnsupportedMethod,
            'T' => if (bytes[1] == 'R' and bytes[2] == 'A' and bytes[4] == 'E')
                Method.TRACE
            else
                error.UnsupportedMethod,
            else => error.UnsupportedMethod,
        },
        6 => if (bytes[0] == 'D' and bytes[1] == 'E' and bytes[2] == 'L' and bytes[3] == 'E' and bytes[4] == 'T' and bytes[5] == 'E')
            Method.DELETE
        else
            error.UnsupportedMethod,
        7 => switch (bytes[0]) {
            'C' => if (bytes[1] == 'O' and bytes[2] == 'N' and bytes[3] == 'N' and bytes[4] == 'E' and bytes[5] == 'C' and bytes[6] == 'T')
                Method.CONNECT
            else
                error.UnsupportedMethod,
            'O' => if (bytes[1] == 'P' and bytes[2] == 'T' and bytes[3] == 'I' and bytes[4] == 'O' and bytes[5] == 'N' and bytes[6] == 'S')
                Method.OPTIONS
            else
                error.UnsupportedMethod,
            else => error.UnsupportedMethod,
        },
        else => error.UnsupportedMethod,
    };
}
