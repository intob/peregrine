const std = @import("std");

/// "date: Sun, 06 Nov 1994 08:49:37 GMT\r\n" (RFC 9110 §5.6.7 IMF-fixdate).
pub const header_len = "date: Sun, 06 Nov 1994 08:49:37 GMT\r\n".len;

pub fn formatHeader(buf: *[header_len]u8, unix_seconds: i64) void {
    const days_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const secs: u64 = @intCast(@max(unix_seconds, 0));
    const days = secs / 86400;
    const rem = secs % 86400;
    const civil = civilFromDays(@intCast(days));
    buf[0..6].* = "date: ".*;
    @memcpy(buf[6..9], days_names[days % 7]);
    buf[9..11].* = ", ".*;
    write2(buf[11..13], civil.day);
    buf[13] = ' ';
    @memcpy(buf[14..17], month_names[civil.month - 1]);
    buf[17] = ' ';
    write2(buf[18..20], @intCast(civil.year / 100));
    write2(buf[20..22], @intCast(civil.year % 100));
    buf[22] = ' ';
    write2(buf[23..25], @intCast(rem / 3600));
    buf[25] = ':';
    write2(buf[26..28], @intCast(rem / 60 % 60));
    buf[28] = ':';
    write2(buf[29..31], @intCast(rem % 60));
    buf[31..header_len].* = " GMT\r\n".*;
}

inline fn write2(out: *[2]u8, v: u32) void {
    out[0] = '0' + @as(u8, @intCast(v / 10));
    out[1] = '0' + @as(u8, @intCast(v % 10));
}

/// Howard Hinnant's days-from-civil inverse.
fn civilFromDays(days: i64) struct { year: u32, month: u32, day: u32 } {
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d = doy - (153 * mp + 2) / 5 + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    return .{
        .year = @intCast(if (m <= 2) y + 1 else y),
        .month = @intCast(m),
        .day = @intCast(d),
    };
}

test "format date header" {
    var buf: [header_len]u8 = undefined;
    formatHeader(&buf, 784111777);
    try std.testing.expectEqualStrings("date: Sun, 06 Nov 1994 08:49:37 GMT\r\n", &buf);
    formatHeader(&buf, 0);
    try std.testing.expectEqualStrings("date: Thu, 01 Jan 1970 00:00:00 GMT\r\n", &buf);
    formatHeader(&buf, 951782400); // leap day
    try std.testing.expectEqualStrings("date: Tue, 29 Feb 2000 00:00:00 GMT\r\n", &buf);
    formatHeader(&buf, 1793059199);
    try std.testing.expectEqualStrings("date: Mon, 26 Oct 2026 23:59:59 GMT\r\n", &buf);
}
