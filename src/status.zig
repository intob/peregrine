pub const Status = enum(u16) {
    switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    teapot = 418,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,

    pub fn isSuccess(self: Status) bool {
        return @intFromEnum(self) >= 200 and @intFromEnum(self) < 300;
    }

    pub fn isRedirect(self: Status) bool {
        return @intFromEnum(self) >= 300 and @intFromEnum(self) < 400;
    }

    pub fn isClientError(self: Status) bool {
        return @intFromEnum(self) >= 400 and @intFromEnum(self) < 500;
    }

    pub fn isServerError(self: Status) bool {
        return @intFromEnum(self) >= 500 and @intFromEnum(self) < 600;
    }

    pub fn toString(self: Status) []const u8 {
        return switch (self) {
            .switching_protocols => "101 Switching Protocols",
            .ok => "200 OK",
            .created => "201 Created",
            .accepted => "202 Accepted",
            .no_content => "204 No Content",
            .moved_permanently => "301 Moved Permanently",
            .found => "302 Found",
            .bad_request => "400 Bad Request",
            .unauthorized => "401 Unauthorized",
            .forbidden => "403 Forbidden",
            .not_found => "404 Not Found",
            .teapot => "418 I'm a teapot",
            .internal_server_error => "500 Internal Server Error",
            .not_implemented => "501 Not Implemented",
            .bad_gateway => "502 Bad Gateway",
            .service_unavailable => "503 Service Unavailable",
        };
    }
};
