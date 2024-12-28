const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;

pub const HandlerVTable = struct {
    handle: *const fn (*anyopaque, *Request, *Response) void,
};
