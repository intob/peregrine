const testing = @import("std").testing;

pub const Header = struct {
    key: []const u8 = undefined,
    value: []const u8 = undefined,

    pub fn parse(raw: []const u8) !Header {
        var h = Header{};
        var pos: usize = 0;
        // Parse key
        while (pos < raw.len) : (pos += 1) {
            if (raw[pos] == ':') {
                h.key = raw[0..pos];
                break;
            }
        } else return error.InvalidHeader;
        // Parse value (+2 skips space after ':')
        h.value = raw[pos + 2 .. raw.len];
        return h;
    }
};

test "parse header" {
    const raw: []const u8 = "Content-Type: text/html";
    const parsed = try Header.parse(raw);
    try testing.expectEqualStrings("Content-Type", parsed.key);
    try testing.expectEqualStrings("text/html", parsed.value);
}
