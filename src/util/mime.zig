const std = @import("std");

const MimeMapping = struct {
    extension: []const u8,
    mime_type: Mime,
};

pub const Mime = enum {
    text_plain,
    text_html,
    text_css,
    application_json,
    application_javascript,
    image_avif,

    const mime_mappings = [_]MimeMapping{
        .{ .extension = ".html", .mime_type = .text_html },
        .{ .extension = ".css", .mime_type = .text_css },
        .{ .extension = ".json", .mime_type = .application_json },
        .{ .extension = ".js", .mime_type = .application_javascript },
        .{ .extension = ".mjs", .mime_type = .application_javascript },
        .{ .extension = ".avif", .mime_type = .image_avif },
    };

    pub fn toString(self: Mime) []const u8 {
        return switch (self) {
            .text_plain => "text/plain",
            .text_html => "text/html",
            .text_css => "text/css",
            .application_json => "application/json",
            .application_javascript => "application/javascript",
            .image_avif => "image/avif",
        };
    }

    pub fn fromExtension(ext: []const u8) Mime {
        for (mime_mappings) |mapping| {
            if (std.mem.eql(u8, ext, mapping.extension)) {
                return mapping.mime_type;
            }
        }
        return .text_plain;
    }
};
