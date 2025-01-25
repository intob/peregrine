const std = @import("std");
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub fn readCertificateFile(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const file_size = stat.size;
    const contents = try file.readToEndAlloc(allocator, file_size);
    defer allocator.free(contents);
    if (!std.mem.startsWith(u8, contents, "-----BEGIN CERTIFICATE-----")) {
        return error.InvalidCertificateFormat;
    }
    return try pemToDer(allocator, contents);
}

pub fn readPrivateKeyFile(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const file_size = stat.size;
    const contents = try file.readToEndAlloc(allocator, file_size);
    defer allocator.free(contents);
    if (!std.mem.startsWith(u8, contents, "-----BEGIN PRIVATE KEY-----") and
        !std.mem.startsWith(u8, contents, "-----BEGIN RSA PRIVATE KEY-----") and
        !std.mem.startsWith(u8, contents, "-----BEGIN EC PRIVATE KEY-----"))
    {
        return error.InvalidKeyFormat;
    }
    return try pemToDer(allocator, contents);
}

fn pemToDer(allocator: std.mem.Allocator, pem_data: []const u8) ![]const u8 {
    const begin_marker = if (std.mem.indexOf(u8, pem_data, "BEGIN")) |i| i else {
        return error.MissingBeginMarker;
    };
    const end_marker = if (std.mem.indexOf(u8, pem_data, "END")) |i| i else {
        return error.MissingEndMarker;
    };
    const content_start = if (std.mem.indexOfPos(u8, pem_data, begin_marker, "-----")) |i|
        i + 5
    else
        return error.InvalidFormat;
    const content_end = if (std.mem.lastIndexOf(u8, pem_data[0..end_marker], "-----")) |i|
        i
    else
        return error.InvalidFormat;
    var raw_content = std.ArrayList(u8).init(allocator);
    defer raw_content.deinit();
    var i: usize = content_start;
    while (i < content_end) : (i += 1) {
        const c = pem_data[i];
        if (!std.ascii.isWhitespace(c)) {
            try raw_content.append(c);
        }
    }
    const der_size = try std.base64.standard.Decoder.calcSizeForSlice(raw_content.items);
    var der = try allocator.alloc(u8, der_size);
    errdefer allocator.free(der);
    _ = &der;
    try std.base64.standard.Decoder.decode(der, raw_content.items);
    return der;
}

pub fn derToKeyPair(der_bytes: []const u8) !EcdsaP256Sha256.KeyPair {
    // DER format for EC private key:
    // - 32 bytes for private scalar
    // - Optional public key point (x,y coordinates)
    const private_scalar = der_bytes[der_bytes.len - 32 ..][0..32].*;
    const secret_key = try EcdsaP256Sha256.SecretKey.fromBytes(private_scalar);
    return try EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key);
}

test "pemToDer certificate" {
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIFaDCCBFCgAwIBAgISESHkvZFwK9Qz0KsXD3x8p44aMA0GCSqGSIb3DQEBCwUA
        \\VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
        \\ggEPADCCAQoCggEBAMGPTyynn77hqcYnjWsMwOZDzdhVFY93s2OJntMbuKTHn39B
        \\bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEF
        \\BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdh
        \\bml6YXRpb252YWxzaGEyZzJyMS5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
        \\lffygD5IymCSuuDim4qB/9bh7oi37heJ4ObpBIzroPUOthbG4gv/5blW3Dc=
        \\-----END CERTIFICATE-----
    ;
    const der = try pemToDer(std.testing.allocator, cert_pem);
    defer std.testing.allocator.free(der);
    try std.testing.expect(der.len > 0);
    // First byte of DER-encoded certificate should be 0x30 (SEQUENCE)
    try std.testing.expectEqual(@as(u8, 0x30), der[0]);
}

test "pemToDer private key" {
    const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
        \\J41rDMDmQ83YVRWPd7NjiZ7TG7ikx59/QW5pemF0aW9udmFsc2hhMmcyLmNybDCB
        \\oAYIKwYBBQUHAQEEgZMwgZAwTQYIKwYBBQUHMAKGQWh0dHA6Ly9zZWN1cmUuZ2xv
        \\YmFsc2lnbi5jb20vY2FjZXJ0L2dzb3JnYW5pemF0aW9udmFsc2hhMmcycjEuY3J0
        \\MD8GCCsGAQUFBzABhjNodHRwOi8vb2NzcJX38oA+SMpgkrrg4puKgf/W4e6It+4X
        \\ieDm6QSM66D1DrYWxuIL/+W5Vtw3
        \\-----END PRIVATE KEY-----
    ;
    const der = try pemToDer(std.testing.allocator, key_pem);
    defer std.testing.allocator.free(der);
    try std.testing.expect(der.len > 0);
    // First byte of DER-encoded private key should be 0x30 (SEQUENCE)
    try std.testing.expectEqual(@as(u8, 0x30), der[0]);
}

test "pemToDer invalid format" {
    const invalid_pem = "not a valid PEM format";
    try std.testing.expectError(error.MissingBeginMarker, pemToDer(std.testing.allocator, invalid_pem));
}
