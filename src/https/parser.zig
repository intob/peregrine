const std = @import("std");
const TLSReader = @import("./reader.zig").TLSReader;

pub const RecordType = enum(u8) {
    handshake = 0x16,
};

pub const HandshakeType = enum(u8) {
    client_hello = 0x01,
    //server_hello = 0x02,
    encrypted_extensions = 0x08,
    certificate = 0x0b,
    certificate_verify = 0x0f,
    finished = 0x14,
    _,
};

pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
    _,
};

pub const Extension = struct {
    extension_type: ExtensionType,
    data: []const u8,
};

pub const ExtensionType = enum(u16) {
    server_name = 0x0000,
    supported_groups = 0x000a,
    signature_algorithms = 0x000d,
    key_share = 0x0033,
    supported_versions = 0x002b,
};

pub const CryptoGroup = enum(u16) {
    x25519 = 0x001d,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519_kyber768d00 = 0x6244,
};

pub const SignatureAlgorithm = enum(u16) {
    // Legacy RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_sha256 = 0x0804,
    rsa_pss_sha384 = 0x0805,
    rsa_pss_sha512 = 0x0806,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,
};

const KeyShare = struct {
    group: CryptoGroup,
    key_exchange: []const u8,
};

pub const ClientHello = struct {
    allocator: std.mem.Allocator,
    random: [32]u8 = undefined,
    session_id: []const u8 = undefined,
    cipher_suites: std.ArrayList(CipherSuite),
    supported_groups: std.ArrayList(CryptoGroup),
    signature_algorithms: std.ArrayList(SignatureAlgorithm),
    key_shares: std.ArrayList(KeyShare),

    pub fn init(allocator: std.mem.Allocator) !*ClientHello {
        const result = try allocator.create(ClientHello);
        result.* = .{
            .allocator = allocator,
            .cipher_suites = std.ArrayList(CipherSuite).init(allocator),
            .supported_groups = std.ArrayList(CryptoGroup).init(allocator),
            .signature_algorithms = std.ArrayList(SignatureAlgorithm).init(allocator),
            .key_shares = std.ArrayList(KeyShare).init(allocator),
        };
        return result;
    }

    pub fn deinit(self: *ClientHello) void {
        self.cipher_suites.deinit();
        self.supported_groups.deinit();
        self.signature_algorithms.deinit();
        self.key_shares.deinit();
        self.allocator.destroy(self);
    }
};

pub fn parseRecord(reader: *TLSReader, fd: i32) !struct { record_type: RecordType, version: u16, data: []const u8 } {
    const header = try reader.read(fd, 5);
    const record_type = header[0];
    const version = std.mem.readInt(u16, header[1..3], .big);
    const length = std.mem.readInt(u16, header[3..5], .big);
    const data = try reader.read(fd, length);
    return .{
        .record_type = @enumFromInt(record_type),
        .version = version,
        .data = data,
    };
}

pub fn parseHandshakeRecord(data: []const u8) !struct { handshake_type: HandshakeType, data: []const u8 } {
    if (data.len < 5) return error.NotEnoughData;
    const len = std.mem.readInt(u24, data[1..4], .big);
    if (data.len - 5 < len) return error.InvalidLength;
    return .{
        .handshake_type = @enumFromInt(data[0]),
        .data = data[5..][0..len],
    };
}

pub fn parseClientHello(allocator: std.mem.Allocator, data: []const u8) !*ClientHello {
    var result = try ClientHello.init(allocator);

    var pos: usize = 4 + 2; // Skip handshake type and length, and legacy version

    @memcpy(&result.random, data[pos..][0..32]);
    pos += 32;

    const session_id_len = data[pos];
    pos += 1;
    result.session_id = data[pos..][0..session_id_len];
    pos += session_id_len;

    const cipher_suites_len = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;
    var i: usize = 0;
    while (i < cipher_suites_len) : (i += 2) {
        const raw = std.mem.readInt(u16, data[pos + i ..][0..2], .big);
        try result.cipher_suites.append(@enumFromInt(raw));
    }
    pos += cipher_suites_len;

    const compression_methods_len = data[pos];
    pos += 1 + compression_methods_len;

    var extensions = std.ArrayList(Extension).init(allocator);
    defer extensions.deinit();
    if (pos < data.len) {
        const extensions_len = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        try parseExtensions(data[pos..][0..extensions_len], &extensions);
    }
    for (extensions.items) |ext| {
        switch (ext.extension_type) {
            .supported_versions => {
                const supports = try parseExtSupportedVersions(ext.data);
                if (!supports.tls_1_3) {
                    return error.NoTLS1_3_Support;
                }
            },
            .supported_groups => try parseExtSupportedGroups(ext.data, &result.supported_groups),
            .signature_algorithms => try parseExtSignatureAlgorithms(ext.data, &result.signature_algorithms),
            .key_share => try parseExtKeyShare(ext.data, &result.key_shares),
            else => std.debug.print("unhandled extension: {}\n", .{ext.extension_type}),
        }
    }

    return result;
}

fn parseExtensions(data: []const u8, extensions: *std.ArrayList(Extension)) !void {
    var pos: usize = 0;
    while (pos < data.len) {
        const ext_type_raw = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        const ext_len = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        defer pos += ext_len;
        const ext_type = std.meta.intToEnum(ExtensionType, ext_type_raw) catch {
            //std.debug.print("skipping unknown extension type: {}\n", .{ext_type_raw});
            continue;
        };
        try extensions.append(.{
            .extension_type = ext_type,
            .data = data[pos..][0..ext_len],
        });
    }
}

fn parseExtSupportedVersions(data: []const u8) !struct { tls_1_3: bool } {
    const TLS_1_3_VERSION = 0x0304;

    if (data.len < 1) return error.InvalidLength;

    // First byte is the length of the version list
    const list_len = data[0];
    if (data.len < 1 + list_len) return error.InvalidLength;

    // Each version is 2 bytes
    if (list_len % 2 != 0) return error.InvalidFormat;

    var has_tls13 = false;
    var i: usize = 1;
    while (i < 1 + list_len) : (i += 2) {
        const version = (@as(u16, data[i]) << 8) | data[i + 1];
        if (version == TLS_1_3_VERSION) {
            has_tls13 = true;
            break;
        }
    }

    return .{ .tls_1_3 = has_tls13 };
}

fn parseExtSupportedGroups(data: []const u8, list: *std.ArrayList(CryptoGroup)) !void {
    if (data.len < 2) return error.InvalidLength;

    // First 2 bytes are the length of the groups list
    const list_len = (@as(u16, data[0]) << 8) | data[1];
    if (data.len < 2 + list_len) return error.InvalidLength;

    // Each group is 2 bytes
    if (list_len % 2 != 0) return error.InvalidFormat;

    var i: usize = 2;
    while (i < 2 + list_len) : (i += 2) {
        const raw = (@as(u16, data[i]) << 8) | data[i + 1];
        const group = std.meta.intToEnum(CryptoGroup, raw) catch {
            //std.debug.print("skipping unsupported group: {}\n", .{raw});
            continue;
        };
        try list.append(group);
    }
}

fn parseExtSignatureAlgorithms(data: []const u8, list: *std.ArrayList(SignatureAlgorithm)) !void {
    if (data.len < 2) return error.InvalidLength;

    // First 2 bytes are the length of the signature algorithms list
    const list_len = (@as(u16, data[0]) << 8) | data[1];
    if (data.len < 2 + list_len) return error.InvalidLength;

    // Each signature algorithm is 2 bytes
    if (list_len % 2 != 0) return error.InvalidFormat;

    var i: usize = 2;
    while (i < 2 + list_len) : (i += 2) {
        const raw = (@as(u16, data[i]) << 8) | data[i + 1];
        const sig_alg = std.meta.intToEnum(SignatureAlgorithm, raw) catch {
            //std.debug.print("skipping unsupported sig alg: {}\n", .{raw});
            continue;
        };
        try list.append(sig_alg);
    }
}

fn parseExtKeyShare(data: []const u8, list: *std.ArrayList(KeyShare)) !void {
    if (data.len < 2) return error.InvalidLength;

    // First 2 bytes are the length of all key share entries
    const list_len = (@as(u16, data[0]) << 8) | data[1];
    if (data.len < 2 + list_len) return error.InvalidLength;

    var offset: usize = 2;
    while (offset < 2 + list_len) {
        if (offset + 4 > data.len) return error.InvalidLength;

        // Parse group (2 bytes)
        const group_id = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;

        // Parse key exchange length (2 bytes)
        const key_exchange_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;

        if (offset + key_exchange_len > data.len) return error.InvalidLength;

        try list.append(.{
            .group = @enumFromInt(group_id),
            .key_exchange = data[offset .. offset + key_exchange_len],
        });

        offset += key_exchange_len;
    }

    if (offset != 2 + list_len) return error.InvalidFormat;
}
