//! Extensible priorities (RFC 9218): the `priority` request header field
//! and the PRIORITY_UPDATE frame's value, a Structured Fields dictionary
//! (RFC 9651 §3.2) whose `u` (urgency) and `i` (incremental) members
//! matter. HTTP/2 and HTTP/3 use it to order response data.
const std = @import("std");

pub const Priority = struct {
    /// 0 is the most urgent, 7 the least (background).
    urgency: u3 = 3,
    /// The client uses the response as it arrives: such responses of
    /// the same urgency share bandwidth instead of going one by one.
    incremental: bool = false,

    /// Applies one field line (or PRIORITY_UPDATE value) on top of `p`:
    /// later members win, as when lines are combined with commas. A value
    /// that fails to parse leaves `p` unchanged and returns false; the
    /// caller then ignores the whole field (RFC 9651 §4.2). Unknown keys,
    /// out-of-range urgencies and values of the wrong type are ignored
    /// (RFC 9218 §4).
    pub fn apply(p: *Priority, value: []const u8) bool {
        var next = p.*;
        var r: Reader = .{ .s = value };
        r.skipSp();
        if (r.done()) return true;
        while (true) {
            const key = r.key() orelse return false;
            var item: Item = .{ .boolean = true };
            if (r.eat('=')) {
                if (r.peek() == '(') {
                    if (!r.innerList()) return false;
                    item = .other;
                } else {
                    item = r.bareItem() orelse return false;
                }
            }
            if (!r.parameters()) return false;
            if (std.mem.eql(u8, key, "u")) {
                switch (item) {
                    .integer => |n| if (n >= 0 and n <= 7) {
                        next.urgency = @intCast(n);
                    },
                    else => {},
                }
            } else if (std.mem.eql(u8, key, "i")) {
                switch (item) {
                    .boolean => |b| next.incremental = b,
                    else => {},
                }
            }
            r.skipOws();
            if (r.done()) break;
            if (!r.eat(',')) return false;
            r.skipOws();
            if (r.done()) return false; // trailing comma
        }
        p.* = next;
        return true;
    }

    /// The priority from every `priority` line among `names`/`values`;
    /// the default if there are none or any fails to parse.
    pub fn fromLines(lines: anytype) Priority {
        var p: Priority = .{};
        var it = lines;
        while (it.next()) |value| {
            if (!p.apply(value)) return .{};
        }
        return p;
    }

    /// Orders responses for sending: more urgent first; at one urgency,
    /// non-incremental ones before incremental ones, which share.
    pub fn before(a: Priority, b: Priority) bool {
        if (a.urgency != b.urgency) return a.urgency < b.urgency;
        return !a.incremental and b.incremental;
    }
};

const Item = union(enum) { integer: i64, boolean: bool, other };

/// RFC 9651 §4.2 parsing, enough to validate any dictionary and keep the
/// integer and boolean values.
const Reader = struct {
    s: []const u8,
    i: usize = 0,

    fn done(r: *const Reader) bool {
        return r.i == r.s.len;
    }

    fn peek(r: *const Reader) u8 {
        return if (r.i < r.s.len) r.s[r.i] else 0;
    }

    fn eat(r: *Reader, c: u8) bool {
        if (r.peek() != c or r.done()) return false;
        r.i += 1;
        return true;
    }

    fn skipSp(r: *Reader) void {
        while (r.i < r.s.len and r.s[r.i] == ' ') r.i += 1;
    }

    fn skipOws(r: *Reader) void {
        while (r.i < r.s.len and (r.s[r.i] == ' ' or r.s[r.i] == '\t')) r.i += 1;
    }

    fn key(r: *Reader) ?[]const u8 {
        const start = r.i;
        const c = r.peek();
        if (!(std.ascii.isLower(c) or c == '*') or r.done()) return null;
        r.i += 1;
        while (r.i < r.s.len) : (r.i += 1) {
            const k = r.s[r.i];
            if (!(std.ascii.isLower(k) or std.ascii.isDigit(k) or k == '_' or k == '-' or k == '.' or k == '*')) break;
        }
        return r.s[start..r.i];
    }

    fn parameters(r: *Reader) bool {
        while (r.eat(';')) {
            r.skipSp();
            _ = r.key() orelse return false;
            if (r.eat('=')) _ = r.bareItem() orelse return false;
        }
        return true;
    }

    fn innerList(r: *Reader) bool {
        if (!r.eat('(')) return false;
        while (true) {
            r.skipSp();
            if (r.eat(')')) return r.parameters();
            _ = r.bareItem() orelse return false;
            if (!r.parameters()) return false;
            const c = r.peek();
            if (c != ' ' and c != ')') return false;
        }
    }

    fn bareItem(r: *Reader) ?Item {
        if (r.done()) return null;
        const c = r.s[r.i];
        if (c == '-' or std.ascii.isDigit(c)) return r.number();
        switch (c) {
            '"' => return if (r.string()) .other else null,
            ':' => return if (r.bytes()) .other else null,
            '?' => {
                r.i += 1;
                if (r.eat('0')) return .{ .boolean = false };
                if (r.eat('1')) return .{ .boolean = true };
                return null;
            },
            '@' => {
                // A date (RFC 9651 §3.3.7): an integer.
                r.i += 1;
                const n = r.number() orelse return null;
                return if (n == .integer) .other else null;
            },
            '%' => return if (r.displayString()) .other else null,
            else => {},
        }
        if (std.ascii.isAlphabetic(c) or c == '*') {
            r.i += 1;
            while (r.i < r.s.len and (isTchar(r.s[r.i]) or r.s[r.i] == ':' or r.s[r.i] == '/')) r.i += 1;
            return .other;
        }
        return null;
    }

    fn number(r: *Reader) ?Item {
        const negative = r.eat('-');
        const start = r.i;
        while (r.i < r.s.len and std.ascii.isDigit(r.s[r.i])) r.i += 1;
        const int_len = r.i - start;
        if (int_len == 0) return null;
        if (r.eat('.')) {
            if (int_len > 12) return null;
            const frac = r.i;
            while (r.i < r.s.len and std.ascii.isDigit(r.s[r.i])) r.i += 1;
            const frac_len = r.i - frac;
            if (frac_len == 0 or frac_len > 3) return null;
            return .other;
        }
        if (int_len > 15) return null;
        const n = std.fmt.parseInt(i64, r.s[start..r.i], 10) catch return null;
        return .{ .integer = if (negative) -n else n };
    }

    fn string(r: *Reader) bool {
        r.i += 1;
        while (r.i < r.s.len) : (r.i += 1) {
            const c = r.s[r.i];
            if (c == '\\') {
                r.i += 1;
                if (r.i == r.s.len or (r.s[r.i] != '"' and r.s[r.i] != '\\')) return false;
            } else if (c == '"') {
                r.i += 1;
                return true;
            } else if (c < 0x20 or c > 0x7e) return false;
        }
        return false;
    }

    fn bytes(r: *Reader) bool {
        r.i += 1;
        while (r.i < r.s.len) : (r.i += 1) {
            const c = r.s[r.i];
            if (c == ':') {
                r.i += 1;
                return true;
            }
            if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=')) return false;
        }
        return false;
    }

    fn displayString(r: *Reader) bool {
        r.i += 1;
        if (!r.eat('"')) return false;
        while (r.i < r.s.len) : (r.i += 1) {
            const c = r.s[r.i];
            if (c == '%') {
                if (r.i + 2 >= r.s.len) return false;
                for (r.s[r.i + 1 ..][0..2]) |h| {
                    if (!(std.ascii.isDigit(h) or (h >= 'a' and h <= 'f'))) return false;
                }
                r.i += 2;
            } else if (c == '"') {
                r.i += 1;
                return true;
            } else if (c < 0x20 or c > 0x7e) return false;
        }
        return false;
    }
};

fn isTchar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null;
}

fn parsed(value: []const u8) ?Priority {
    var p: Priority = .{};
    return if (p.apply(value)) p else null;
}

test "priority: urgency and incremental, defaults, unknown members" {
    const t = std.testing;
    try t.expectEqual(Priority{}, parsed("").?);
    try t.expectEqual(Priority{ .urgency = 0 }, parsed("u=0").?);
    try t.expectEqual(Priority{ .urgency = 5, .incremental = true }, parsed("u=5, i").?);
    try t.expectEqual(Priority{ .incremental = true }, parsed("i=?1").?);
    try t.expectEqual(Priority{}, parsed("i=?0").?);
    try t.expectEqual(Priority{ .urgency = 1 }, parsed("  u=1;x=\"y\";z, foo=(a \"b\" 1.5);q=:AAA=:, bar=@1700000000, baz=%\"%c3%a9\"").?);
    // The last member wins.
    try t.expectEqual(Priority{ .urgency = 2 }, parsed("u=6, u=2").?);
    // Out of range or the wrong type: ignored, the rest applies.
    try t.expectEqual(Priority{ .incremental = true }, parsed("u=8, i").?);
    try t.expectEqual(Priority{}, parsed("u=-1").?);
    try t.expectEqual(Priority{}, parsed("u=1.0, i=1, u=\"1\", u=?1, u=tok").?);
    try t.expectEqual(Priority{ .urgency = 7 }, parsed("u=7, i=x").?);
    // Lines combine.
    var p: Priority = .{};
    try t.expect(p.apply("u=1"));
    try t.expect(p.apply("i"));
    try t.expectEqual(Priority{ .urgency = 1, .incremental = true }, p);
}

test "priority: malformed dictionaries are ignored whole" {
    const t = std.testing;
    for ([_][]const u8{
        "u=1,",               "U=1",      "u=",     "u=1 i", "u=1,,i",    ",u=1",   "u=1;",    "u==1",     "1=u",         "\tu=1",
        "u=1234567890123456", "u=\"open", "u=:abc", "i=?2",  "u=1, x=(a", "x=(a)b", "u=1\x00", "x=1.2345", "x=%\"\xc3\"", "u=1;A",
        "x=\"\\a\"",
    }) |v| {
        var p: Priority = .{ .urgency = 6 };
        const ok = p.apply(v);
        if (ok) {
            std.debug.print("accepted: {s}\n", .{v});
            return error.TestUnexpectedResult;
        }
        try t.expectEqual(Priority{ .urgency = 6 }, p);
    }
    // OWS around commas and trailing spaces are fine.
    try t.expectEqual(Priority{ .urgency = 1, .incremental = true }, parsed("u=1\t,\ti  ").?);
}

test "priority: ordering" {
    const t = std.testing;
    try t.expect(Priority.before(.{ .urgency = 1, .incremental = true }, .{ .urgency = 2 }));
    try t.expect(Priority.before(.{ .urgency = 3 }, .{ .urgency = 3, .incremental = true }));
    try t.expect(!Priority.before(.{ .urgency = 3, .incremental = true }, .{ .urgency = 3, .incremental = true }));
    try t.expect(!Priority.before(.{ .urgency = 3 }, .{ .urgency = 3 }));
}
