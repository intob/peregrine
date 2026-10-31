//! OCSP stapling (RFC 6066 §8, RFC 6960; in TLS 1.3, RFC 8446 §4.4.2.1):
//! a client that sends status_request gets the server's OCSP response for
//! its certificate in the leaf's CertificateEntry, so it need not ask the
//! CA's responder itself.
//!
//! `check` decides whether a DER OCSPResponse may be stapled for a
//! certificate chain: it parses, its status is successful, it is a basic
//! response with a SingleResponse for the leaf (CertID: the issuer's name
//! and key hashes, with SHA-1 or SHA-2, and the serial number), it is
//! signed by the issuer or by a responder the issuer delegated to (RFC
//! 6960 §4.2.2.2), the certificate is good (not revoked, not unknown), it
//! hasn't expired and it isn't from the future. A client that checks the
//! response would refuse anything else, so it isn't stapled. `check` runs
//! when a response is loaded (`src/ocsp_watcher.zig`), never per
//! handshake.
//!
//! `Staple` holds one certificate's response, prepared once per load as
//! the CertificateEntry extension, for the handshakes of every worker:
//! readers take a slot without locks or allocation, and a new response is
//! written to the other slot (see `Staple`). Loading files is not done
//! here (I/O-free).
const std = @import("std");
const sys = @import("../sys.zig");
const ExtensionType = std.crypto.tls.ExtensionType;
const rsa = std.crypto.Certificate.rsa;
const Ed25519 = std.crypto.sign.Ed25519;

/// The largest response stapled: what CertificateEntry.extensions'
/// 16-bit length leaves room for after the extension's type and length,
/// status_type and the response's 24-bit length (`entryLen`).
pub const max_response_len = 0xffff - 8;

/// Without nextUpdate (RFC 6960 §4.2.2.1: newer information is always
/// available) a response is stapled for this long after thisUpdate.
pub const default_validity_s = 24 * 3600;

/// How far ahead of our clock thisUpdate and producedAt may be (curl's
/// OCSP_check_validity allows the same).
pub const max_clock_skew_s = 300;

pub const Error = error{
    /// Not DER, or not an OCSPResponse.
    Malformed,
    /// responseStatus other than successful (no response inside).
    NotSuccessful,
    /// A response type other than id-pkix-ocsp-basic.
    NotBasic,
    /// The certificate chain has no issuer for the leaf (by name), so
    /// neither the CertID nor the signature can be checked.
    NoIssuer,
    /// The leaf certificate itself doesn't parse (strictly).
    InvalidCertificate,
    /// No SingleResponse is for the leaf.
    NotForCertificate,
    /// The only CertID for the leaf is hashed with SHA-2: OpenSSL clients
    /// (curl --cert-status) look up a SHA-1 one and find no status. Fetch
    /// with SHA-1 (`openssl ocsp` does by default).
    NoSha1CertId,
    /// The responder is neither the issuer the CertID names nor a
    /// responder it delegated to: a certificate in the response that the
    /// issuer signed, with id-kp-OCSPSigning (and, if it has keyUsage,
    /// digitalSignature; no critical extension a client wouldn't know). A
    /// response about several issuers' certificates must be signed by the
    /// issuer itself.
    UnauthorizedResponder,
    /// The delegated responder's certificate isn't valid now (before its
    /// notBefore, or past its notAfter: OpenSSL allows no skew here).
    ResponderNotCurrent,
    /// The responder's signature (or the issuer's on the responder's
    /// certificate) doesn't verify.
    BadSignature,
    /// A signature algorithm or key that isn't supported: RSA (2048, 3072
    /// or 4096 bits) with PKCS#1 v1.5 or PSS, ECDSA P-256 or P-384, each
    /// with SHA-256, SHA-384 or SHA-512; Ed25519.
    UnsupportedAlgorithm,
    Revoked,
    StatusUnknown,
    /// nextUpdate has passed.
    Expired,
    /// thisUpdate or producedAt is more than `max_clock_skew_s` ahead.
    NotYetValid,
    TooLarge,
};

pub const Checked = struct {
    /// Seconds since the epoch.
    this_update: i64,
    /// Stapled until this second: nextUpdate, or thisUpdate plus
    /// `default_validity_s` without one (or the delegated responder's
    /// certificate's notAfter, if sooner).
    expires: i64,
};

pub const Status = enum { good, revoked, unknown };

/// What `verify` found in a response that parses, is for the leaf and is
/// properly signed: what is left to decide depends only on the time
/// (`evaluate`).
pub const Verified = struct {
    status: Status,
    this_update: i64,
    next_update: ?i64,
    produced_at: i64,
    /// A delegated responder's certificate's validity (unbounded when the
    /// issuer signed).
    signer_not_before: i64 = std.math.minInt(i64),
    signer_not_after: i64 = std.math.maxInt(i64),
};

const oid_ocsp_basic = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
const oid_kp_ocsp_signing = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
const oid_ext_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25 };
const oid_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_ext_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
const oid_ext_subject_key_id = [_]u8{ 0x55, 0x1d, 0x0e };
const oid_ext_authority_key_id = [_]u8{ 0x55, 0x1d, 0x23 };
const oid_ext_certificate_policies = [_]u8{ 0x55, 0x1d, 0x20 };
const oid_ext_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };
const oid_ext_name_constraints = [_]u8{ 0x55, 0x1d, 0x1e };
const oid_pkix_ocsp_nocheck = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05 };
const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const oid_sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const oid_sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_mgf1 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08 };
const oid_rsa_pss = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
const oid_sha256_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_sha384_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const oid_sha512_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ecdsa_sha384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
const oid_ecdsa_sha512 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

const tag = struct {
    const boolean = 0x01;
    const integer = 0x02;
    const bit_string = 0x03;
    const octet_string = 0x04;
    const null_ = 0x05;
    const oid = 0x06;
    const enumerated = 0x0a;
    const utc_time = 0x17;
    const generalized_time = 0x18;
    const sequence = 0x30;
    /// Context-specific [n], constructed (EXPLICIT, or IMPLICIT over a
    /// constructed type).
    const ctx0 = 0xa0;
    const ctx1 = 0xa1;
    const ctx2 = 0xa2;
    const ctx3 = 0xa3;
    /// CertStatus: good and unknown are [0] and [2] IMPLICIT NULL.
    const good = 0x80;
    const unknown = 0x82;
    /// TBSCertificate's issuerUniqueID and subjectUniqueID.
    const issuer_uid = 0x81;
    const subject_uid = 0x82;
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Strict DER: definite lengths in their shortest form, every element
/// inside its parent, nothing left over where a structure ends.
const Der = struct {
    bytes: []const u8,
    pos: usize = 0,

    const Element = struct {
        tag: u8,
        contents: []const u8,
        /// Tag, length and contents.
        all: []const u8,
    };

    fn atEnd(self: *const Der) bool {
        return self.pos == self.bytes.len;
    }

    fn peekTag(self: *const Der) ?u8 {
        return if (self.atEnd()) null else self.bytes[self.pos];
    }

    fn next(self: *Der) Error!Element {
        const rest = self.bytes[self.pos..];
        if (rest.len < 2) return error.Malformed;
        const t = rest[0];
        // High tag numbers (31 and up) appear nowhere here.
        if (t & 0x1f == 0x1f) return error.Malformed;
        var i: usize = 2;
        var len: usize = rest[1];
        if (len & 0x80 != 0) {
            // Up to 3 length bytes (16 MiB); 0x80 alone is BER's
            // indefinite length.
            const n = len & 0x7f;
            if (n == 0 or n > 3 or rest.len - i < n) return error.Malformed;
            if (rest[i] == 0) return error.Malformed;
            len = 0;
            for (rest[i..][0..n]) |b| len = len << 8 | b;
            i += n;
            if (len < 0x80) return error.Malformed;
        }
        if (rest.len - i < len) return error.Malformed;
        self.pos += i + len;
        return .{ .tag = t, .contents = rest[i..][0..len], .all = rest[0 .. i + len] };
    }

    fn expect(self: *Der, t: u8) Error![]const u8 {
        return (try self.expectElement(t)).contents;
    }

    fn expectElement(self: *Der, t: u8) Error!Element {
        const e = try self.next();
        if (e.tag != t) return error.Malformed;
        return e;
    }

    fn optional(self: *Der, t: u8) Error!?[]const u8 {
        if (self.peekTag() != t) return null;
        return try self.expect(t);
    }

    fn end(self: *const Der) Error!void {
        if (!self.atEnd()) return error.Malformed;
    }
};

/// A BIT STRING's bits, whole bytes only.
fn bitString(b: []const u8) Error![]const u8 {
    if (b.len < 1 or b[0] != 0) return error.Malformed;
    return b[1..];
}

/// An Extension's contents (RFC 5280 §4.1): extnID, critical (DEFAULT
/// FALSE, also accepted written out), extnValue.
fn extension(contents: []const u8) Error!struct { id: []const u8, critical: bool, value: []const u8 } {
    var ext: Der = .{ .bytes = contents };
    const id = try ext.expect(tag.oid);
    var critical = false;
    if (try ext.optional(tag.boolean)) |b| {
        // Any nonzero value is TRUE (BER; OpenSSL takes it too).
        if (b.len != 1) return error.Malformed;
        critical = b[0] != 0;
    }
    const value = try ext.expect(tag.octet_string);
    try ext.end();
    return .{ .id = id, .critical = critical, .value = value };
}

/// Extensions (a SEQUENCE OF Extension) inside an EXPLICIT tag's
/// contents: each must parse (a client parses them all).
fn checkExtensions(explicit: []const u8) Error!void {
    var outer: Der = .{ .bytes = explicit };
    var list: Der = .{ .bytes = try outer.expect(tag.sequence) };
    try outer.end();
    if (list.atEnd()) return error.Malformed;
    while (!list.atEnd()) _ = try extension(try list.expect(tag.sequence));
}

/// Checks the value of the extensions a responder's certificate is judged
/// by (an error: malformed, which OpenSSL takes as an invalid
/// certificate); false for an extension a client wouldn't know (so a
/// critical one refuses the certificate). Never stricter than OpenSSL: a
/// responder we refuse and clients accept could sign a revocation we
/// wouldn't act on.
fn extensionValue(id: []const u8, value: []const u8, ocsp_signing: *bool) Error!bool {
    var v: Der = .{ .bytes = value };
    if (eql(id, &oid_ext_ext_key_usage)) {
        // SEQUENCE SIZE (1..MAX) OF KeyPurposeId.
        var purposes: Der = .{ .bytes = try v.expect(tag.sequence) };
        try v.end();
        if (purposes.atEnd()) return error.Malformed;
        while (!purposes.atEnd()) {
            if (eql(try purposes.expect(tag.oid), &oid_kp_ocsp_signing)) ocsp_signing.* = true;
        }
    } else if (eql(id, &oid_ext_key_usage)) {
        // A BIT STRING (OpenSSL doesn't ask a responder for
        // digitalSignature, nor the named-bit DER rules).
        const bits = try v.expect(tag.bit_string);
        try v.end();
        if (bits.len < 1 or bits[0] > 7 or (bits.len == 1 and bits[0] != 0)) return error.Malformed;
    } else if (eql(id, &oid_ext_basic_constraints)) {
        // SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER
        // (0..MAX) OPTIONAL }; DER leaves FALSE out.
        var bc: Der = .{ .bytes = try v.expect(tag.sequence) };
        try v.end();
        if (try bc.optional(tag.boolean)) |b| {
            if (b.len != 1 or b[0] != 0xff) return error.Malformed;
        }
        if (try bc.optional(tag.integer)) |n| {
            if (n.len == 0 or n[0] & 0x80 != 0) return error.Malformed;
        }
        try bc.end();
    } else if (eql(id, &oid_ext_subject_key_id)) {
        _ = try v.expect(tag.octet_string);
        try v.end();
    } else if (eql(id, &oid_ext_authority_key_id)) {
        // SEQUENCE { keyIdentifier [0] OPTIONAL, authorityCertIssuer [1]
        // OPTIONAL, authorityCertSerialNumber [2] OPTIONAL }, the last two
        // together.
        var aki: Der = .{ .bytes = try v.expect(tag.sequence) };
        try v.end();
        _ = try aki.optional(0x80);
        const issuer = try aki.optional(tag.ctx1);
        const serial = try aki.optional(0x82);
        try aki.end();
        if ((issuer == null) != (serial == null)) return error.Malformed;
    } else if (!eql(id, &oid_pkix_ocsp_nocheck) and !eql(id, &oid_ext_certificate_policies) and
        !eql(id, &oid_ext_subject_alt_name) and !eql(id, &oid_ext_name_constraints))
    {
        return false;
    }
    return true;
}

/// The parts of an X.509 certificate (RFC 5280 §4.1) used here: what a
/// CertID is made from, and what checking a responder needs.
const Cert = struct {
    /// tbsCertificate as signed (tag and length included).
    tbs: []const u8,
    /// AlgorithmIdentifier contents.
    sig_alg: []const u8,
    signature: []const u8,
    serial: []const u8,
    /// Names, DER (tag and length included).
    issuer: []const u8,
    subject: []const u8,
    not_before: i64,
    not_after: i64,
    /// subjectPublicKeyInfo (whole), its AlgorithmIdentifier contents and
    /// key bits.
    spki: []const u8,
    key_alg: []const u8,
    public_key: []const u8,
    /// Extended key usage includes id-kp-OCSPSigning.
    ocsp_signing: bool,
    /// A critical extension other than keyUsage, extKeyUsage and
    /// basicConstraints (which a client would refuse in a responder's
    /// certificate it doesn't understand).
    unknown_critical: bool,
    /// What RFC 5280 says to reject and OpenSSL does: an extension twice
    /// (§4.2), tbsCertificate.signature other than signatureAlgorithm
    /// (§4.1.1.2), a version that doesn't fit what is there, an empty
    /// extKeyUsage, keyUsage, subjectKeyIdentifier, authorityKeyIdentifier
    /// or basicConstraints that isn't DER.
    invalid: bool,

    const max_extensions = 64;

    fn parse(der: []const u8) Error!Cert {
        var outer: Der = .{ .bytes = der };
        var cert: Der = .{ .bytes = try outer.expect(tag.sequence) };
        try outer.end();
        const tbs_el = try cert.expectElement(tag.sequence);
        const sig_alg = try cert.expect(tag.sequence);
        const signature = try bitString(try cert.expect(tag.bit_string));
        try cert.end();
        var tbs: Der = .{ .bytes = tbs_el.contents };
        // Version: v1 (0, and DER leaves it out), v2 (1), v3 (2).
        var version: u8 = 0;
        if (try tbs.optional(tag.ctx0)) |v| {
            var vd: Der = .{ .bytes = v };
            const n = try vd.expect(tag.integer);
            try vd.end();
            if (n.len != 1 or n[0] > 2) return error.Malformed;
            version = n[0];
        }
        const serial = try tbs.expect(tag.integer);
        if (serial.len == 0) return error.Malformed;
        const tbs_sig_alg = try tbs.expect(tag.sequence);
        const issuer = try tbs.expectElement(tag.sequence);
        var validity: Der = .{ .bytes = try tbs.expect(tag.sequence) };
        const not_before = try parseCertTime(try validity.next());
        const not_after = try parseCertTime(try validity.next());
        try validity.end();
        const subject = try tbs.expectElement(tag.sequence);
        const spki_el = try tbs.expectElement(tag.sequence);
        var spki: Der = .{ .bytes = spki_el.contents };
        const key_alg = try spki.expect(tag.sequence);
        const public_key = try bitString(try spki.expect(tag.bit_string));
        try spki.end();
        const uids = (try tbs.optional(tag.issuer_uid) != null) or (try tbs.optional(tag.subject_uid) != null);
        var ocsp_signing = false;
        var unknown_critical = false;
        var invalid = !eql(tbs_sig_alg, sig_alg) or (uids and version < 1);
        if (try tbs.optional(tag.ctx3)) |e| {
            if (version != 2) invalid = true;
            var exts_outer: Der = .{ .bytes = e };
            var exts: Der = .{ .bytes = try exts_outer.expect(tag.sequence) };
            try exts_outer.end();
            if (exts.atEnd()) return error.Malformed;
            var seen: [max_extensions][]const u8 = undefined;
            var seen_len: usize = 0;
            while (!exts.atEnd()) {
                const x = try extension(try exts.expect(tag.sequence));
                for (seen[0..seen_len]) |o| {
                    if (eql(o, x.id)) invalid = true;
                }
                // More than any real certificate has: refused rather
                // than checked in part.
                if (seen_len == seen.len) {
                    invalid = true;
                } else {
                    seen[seen_len] = x.id;
                    seen_len += 1;
                }
                const known = extensionValue(x.id, x.value, &ocsp_signing) catch {
                    invalid = true;
                    continue;
                };
                if (!known and x.critical) unknown_critical = true;
            }
        }
        try tbs.end();
        return .{
            .tbs = tbs_el.all,
            .sig_alg = sig_alg,
            .signature = signature,
            .serial = serial,
            .issuer = issuer.all,
            .subject = subject.all,
            .not_before = not_before,
            .not_after = not_after,
            .spki = spki_el.all,
            .key_alg = key_alg,
            .public_key = public_key,
            .ocsp_signing = ocsp_signing,
            .unknown_critical = unknown_critical,
            .invalid = invalid,
        };
    }
};

/// The leaf and the certificates in the chain named as its issuer.
const Subject = struct {
    leaf: Cert,
    issuers: [max_issuers]Cert = undefined,
    issuer_count: usize = 0,

    const max_issuers = 4;

    fn init(chain: []const []const u8) Error!Subject {
        if (chain.len == 0) return error.NoIssuer;
        var s: Subject = .{ .leaf = Cert.parse(chain[0]) catch return error.InvalidCertificate };
        for (chain[1..]) |c| {
            const issuer = Cert.parse(c) catch continue;
            if (!eql(issuer.subject, s.leaf.issuer)) continue;
            if (s.issuer_count == max_issuers) break;
            s.issuers[s.issuer_count] = issuer;
            s.issuer_count += 1;
        }
        if (s.issuer_count == 0) return error.NoIssuer;
        return s;
    }

    fn issuerSlice(s: *const Subject) []const Cert {
        return s.issuers[0..s.issuer_count];
    }
};

const Hash = enum { sha1, sha256, sha384, sha512 };

fn HashType(comptime h: Hash) type {
    return switch (h) {
        .sha1 => std.crypto.hash.Sha1,
        .sha256 => std.crypto.hash.sha2.Sha256,
        .sha384 => std.crypto.hash.sha2.Sha384,
        .sha512 => std.crypto.hash.sha2.Sha512,
    };
}

fn hashFromOid(oid: []const u8) ?Hash {
    if (eql(oid, &oid_sha1)) return .sha1;
    if (eql(oid, &oid_sha256)) return .sha256;
    if (eql(oid, &oid_sha384)) return .sha384;
    if (eql(oid, &oid_sha512)) return .sha512;
    return null;
}

fn hashEql(h: Hash, data: []const u8, expected: []const u8) bool {
    switch (h) {
        inline else => |hh| {
            const H = HashType(hh);
            if (expected.len != H.digest_length) return false;
            var d: [H.digest_length]u8 = undefined;
            H.hash(data, &d, .{});
            return eql(&d, expected);
        },
    }
}

/// A hash AlgorithmIdentifier's contents: the OID, parameters NULL or
/// absent.
fn hashAlgorithm(alg: []const u8) Error!?Hash {
    var a: Der = .{ .bytes = alg };
    const oid = try a.expect(tag.oid);
    if (try a.optional(tag.null_)) |p| if (p.len != 0) return error.Malformed;
    try a.end();
    return hashFromOid(oid);
}

const CertId = struct {
    /// hashAlgorithm, issuerNameHash, issuerKeyHash: which issuer.
    alg: []const u8,
    name_hash: []const u8,
    key_hash: []const u8,
    serial: []const u8,

    fn parse(der: []const u8) Error!CertId {
        var id: Der = .{ .bytes = der };
        const alg = try id.expect(tag.sequence);
        _ = try hashAlgorithm(alg);
        const name_hash = try id.expect(tag.octet_string);
        const key_hash = try id.expect(tag.octet_string);
        const serial = try id.expect(tag.integer);
        try id.end();
        return .{ .alg = alg, .name_hash = name_hash, .key_hash = key_hash, .serial = serial };
    }

    fn sameIssuer(a: CertId, b: CertId) bool {
        return eql(a.alg, b.alg) and eql(a.name_hash, b.name_hash) and eql(a.key_hash, b.key_hash);
    }

    /// The issuer (among `s`'s) whose key it names, if it is for `s`'s
    /// leaf, and whether it is hashed with SHA-1.
    fn issuer(id: CertId, s: *const Subject) ?struct { cert: *const Cert, sha1: bool } {
        if (!eql(id.serial, s.leaf.serial)) return null;
        const hash = (hashAlgorithm(id.alg) catch unreachable) orelse return null;
        if (!hashEql(hash, s.leaf.issuer, id.name_hash)) return null;
        for (s.issuerSlice()) |*c| {
            if (hashEql(hash, c.public_key, id.key_hash)) return .{ .cert = c, .sha1 = hash == .sha1 };
        }
        return null;
    }
};

const SignatureAlgorithm = union(enum) {
    rsa_pkcs1: Hash,
    /// MGF1 with the same hash and a salt as long as the hash.
    rsa_pss: Hash,
    ecdsa: Hash,
    ed25519,
};

fn signatureAlgorithm(alg: []const u8) Error!SignatureAlgorithm {
    var a: Der = .{ .bytes = alg };
    const oid = try a.expect(tag.oid);
    if (eql(oid, &oid_ed25519)) {
        try a.end();
        return .ed25519;
    }
    const Named = struct { oid: []const u8, hash: Hash };
    for ([_]Named{ .{ .oid = &oid_ecdsa_sha256, .hash = .sha256 }, .{ .oid = &oid_ecdsa_sha384, .hash = .sha384 }, .{ .oid = &oid_ecdsa_sha512, .hash = .sha512 } }) |c| {
        if (eql(oid, c.oid)) {
            try a.end();
            return .{ .ecdsa = c.hash };
        }
    }
    for ([_]Named{ .{ .oid = &oid_sha256_rsa, .hash = .sha256 }, .{ .oid = &oid_sha384_rsa, .hash = .sha384 }, .{ .oid = &oid_sha512_rsa, .hash = .sha512 } }) |c| {
        if (eql(oid, c.oid)) {
            if (try a.optional(tag.null_)) |p| if (p.len != 0) return error.Malformed;
            try a.end();
            return .{ .rsa_pkcs1 = c.hash };
        }
    }
    if (!eql(oid, &oid_rsa_pss)) return error.UnsupportedAlgorithm;
    // RSASSA-PSS-params (RFC 4055 §3.1). The defaults (SHA-1, a 20-byte
    // salt) aren't supported, so every field but trailerField is there.
    var params: Der = .{ .bytes = try a.expect(tag.sequence) };
    try a.end();
    var hash_explicit: Der = .{ .bytes = try params.expect(tag.ctx0) };
    const hash = (try hashAlgorithm(try hash_explicit.expect(tag.sequence))) orelse return error.UnsupportedAlgorithm;
    try hash_explicit.end();
    var mgf_explicit: Der = .{ .bytes = try params.expect(tag.ctx1) };
    var mgf: Der = .{ .bytes = try mgf_explicit.expect(tag.sequence) };
    try mgf_explicit.end();
    if (!eql(try mgf.expect(tag.oid), &oid_mgf1)) return error.UnsupportedAlgorithm;
    const mgf_hash = try hashAlgorithm(try mgf.expect(tag.sequence));
    try mgf.end();
    var salt_explicit: Der = .{ .bytes = try params.expect(tag.ctx2) };
    const salt = try salt_explicit.expect(tag.integer);
    try salt_explicit.end();
    if (try params.optional(tag.ctx3)) |t| {
        var trailer: Der = .{ .bytes = t };
        if (!eql(try trailer.expect(tag.integer), &.{1})) return error.UnsupportedAlgorithm;
        try trailer.end();
    }
    try params.end();
    const hash_len: u8 = switch (hash) {
        inline else => |hh| HashType(hh).digest_length,
    };
    if (hash == .sha1 or mgf_hash != hash or !eql(salt, &.{hash_len})) return error.UnsupportedAlgorithm;
    return .{ .rsa_pss = hash };
}

/// Checks `signature` over `msg` with the key in a subjectPublicKeyInfo
/// (`key_alg`, `public_key`), by the AlgorithmIdentifier `alg`.
fn verifySignature(alg: []const u8, key_alg: []const u8, public_key: []const u8, msg: []const u8, signature: []const u8) Error!void {
    const sig_alg = try signatureAlgorithm(alg);
    var k: Der = .{ .bytes = key_alg };
    const key_oid = try k.expect(tag.oid);
    // Other keys (RSASSA-PSS keys among them) aren't supported.
    if (!eql(key_oid, &oid_rsa_encryption) and !eql(key_oid, &oid_ec_public_key) and !eql(key_oid, &oid_ed25519))
        return error.UnsupportedAlgorithm;
    switch (sig_alg) {
        .ed25519 => {
            if (!eql(key_oid, &oid_ed25519)) return error.BadSignature;
            if (public_key.len != 32 or signature.len != 64) return error.BadSignature;
            const pk = Ed25519.PublicKey.fromBytes(public_key[0..32].*) catch return error.BadSignature;
            Ed25519.Signature.fromBytes(signature[0..64].*).verify(msg, pk) catch return error.BadSignature;
        },
        .ecdsa => |h| {
            if (!eql(key_oid, &oid_ec_public_key)) return error.BadSignature;
            const curve = try k.expect(tag.oid);
            if (eql(curve, &oid_p256)) return verifyEcdsa(std.crypto.ecc.P256, h, public_key, msg, signature);
            if (eql(curve, &oid_p384)) return verifyEcdsa(std.crypto.ecc.P384, h, public_key, msg, signature);
            return error.UnsupportedAlgorithm;
        },
        .rsa_pkcs1, .rsa_pss => |h| {
            if (!eql(key_oid, &oid_rsa_encryption)) return error.BadSignature;
            var key_der: Der = .{ .bytes = public_key };
            var key: Der = .{ .bytes = try key_der.expect(tag.sequence) };
            try key_der.end();
            const modulus = std.mem.trimStart(u8, try key.expect(tag.integer), &.{0});
            const exponent = std.mem.trimStart(u8, try key.expect(tag.integer), &.{0});
            try key.end();
            // std's PSS check asserts the encoded message fills the
            // modulus's bytes, which isn't so for a modulus of 8k + 1 bits
            // (top byte 1; rsa_verify.zig skips these sizes too).
            if (modulus.len == 0) return error.Malformed;
            if (sig_alg == .rsa_pss and modulus[0] == 1) return error.UnsupportedAlgorithm;
            const pk = rsa.PublicKey.fromBytes(exponent, modulus) catch return error.UnsupportedAlgorithm;
            if (signature.len != modulus.len) return error.BadSignature;
            switch (modulus.len) {
                inline 256, 384, 512 => |len| switch (h) {
                    .sha1 => return error.UnsupportedAlgorithm,
                    inline else => |hh| {
                        const sig = signature[0..len];
                        if (sig_alg == .rsa_pss) {
                            rsa.PSSSignature.verify(len, sig, msg, pk, HashType(hh)) catch return error.BadSignature;
                        } else {
                            rsa.PKCS1v1_5Signature.verify(len, sig, msg, pk, HashType(hh)) catch return error.BadSignature;
                        }
                    },
                },
                else => return error.UnsupportedAlgorithm,
            }
        },
    }
}

fn verifyEcdsa(comptime Curve: type, h: Hash, public_key: []const u8, msg: []const u8, signature: []const u8) Error!void {
    switch (h) {
        .sha1 => return error.UnsupportedAlgorithm,
        inline else => |hh| {
            const Scheme = std.crypto.sign.ecdsa.Ecdsa(Curve, HashType(hh));
            const pk = Scheme.PublicKey.fromSec1(public_key) catch return error.BadSignature;
            // Ecdsa-Sig-Value as DER has it (std's fromDer lets a needless
            // leading 0, or a negative r or s, through; OpenSSL doesn't).
            var outer: Der = .{ .bytes = signature };
            var rs: Der = .{ .bytes = outer.expect(tag.sequence) catch return error.BadSignature };
            outer.end() catch return error.BadSignature;
            for (0..2) |_| {
                const n = rs.expect(tag.integer) catch return error.BadSignature;
                if (n.len == 0 or n[0] & 0x80 != 0 or (n.len > 1 and n[0] == 0 and n[1] & 0x80 == 0)) return error.BadSignature;
            }
            rs.end() catch return error.BadSignature;
            const sig = Scheme.Signature.fromDer(signature) catch return error.BadSignature;
            sig.verify(msg, pk) catch return error.BadSignature;
        },
    }
}

/// ResponderID (RFC 6960 §4.2.2.3): byName [1] or byKey [2] (the SHA-1 of
/// the key bits) names `c`.
fn responderIs(responder: Der.Element, c: *const Cert) Error!bool {
    var r: Der = .{ .bytes = responder.contents };
    if (responder.tag == tag.ctx1) {
        const name = try r.expectElement(tag.sequence);
        try r.end();
        return eql(name.all, c.subject);
    }
    const key_hash = try r.expect(tag.octet_string);
    try r.end();
    return hashEql(.sha1, c.public_key, key_hash);
}

/// RFC 6960 §4.2.2.2, decided as OpenSSL does (stapling a response a
/// client refuses is worse than none): a ResponderID that names an issuer
/// in the chain means that issuer signed, and it must be the one whose key
/// the CertID names (`cert_issuer`, as ocsp_match_issuerid requires).
/// Otherwise the first certificate in `certs` the ResponderID names must
/// be one `cert_issuer` signed with id-kp-OCSPSigning, and the response
/// must be about that issuer's certificates only. Returns the delegated
/// responder certificate's validity (the time is `evaluate`'s to judge).
fn checkSigner(
    s: *const Subject,
    cert_issuer: *const Cert,
    responder: Der.Element,
    sig_alg: []const u8,
    tbs: []const u8,
    signature: []const u8,
    certs: ?[]const u8,
    several_issuers: bool,
) Error![2]i64 {
    for (s.issuerSlice()) |*issuer| {
        if (!try responderIs(responder, issuer)) continue;
        if (!try responderIs(responder, cert_issuer)) return error.UnauthorizedResponder;
        try verifySignature(sig_alg, cert_issuer.key_alg, cert_issuer.public_key, tbs, signature);
        return .{ std.math.minInt(i64), std.math.maxInt(i64) };
    }
    if (several_issuers) return error.UnauthorizedResponder;
    const list = certs orelse return error.UnauthorizedResponder;
    var explicit: Der = .{ .bytes = list };
    var seq: Der = .{ .bytes = try explicit.expect(tag.sequence) };
    try explicit.end();
    while (!seq.atEnd()) {
        const c = try Cert.parse((try seq.expectElement(tag.sequence)).all);
        if (!try responderIs(responder, &c)) continue;
        try delegatedBy(&c, cert_issuer);
        try verifySignature(sig_alg, c.key_alg, c.public_key, tbs, signature);
        return .{ c.not_before, c.not_after };
    }
    return error.UnauthorizedResponder;
}

/// Every certificate in a certs field parses (a client parses them all).
fn checkCerts(explicit: []const u8) Error!void {
    var outer: Der = .{ .bytes = explicit };
    var seq: Der = .{ .bytes = try outer.expect(tag.sequence) };
    try outer.end();
    while (!seq.atEnd()) _ = try Cert.parse((try seq.expectElement(tag.sequence)).all);
}

/// `c` is a responder certificate `issuer` issued for OCSP signing.
fn delegatedBy(c: *const Cert, issuer: *const Cert) Error!void {
    if (!c.ocsp_signing or c.unknown_critical or c.invalid or !eql(c.issuer, issuer.subject)) return error.UnauthorizedResponder;
    verifySignature(c.sig_alg, issuer.key_alg, issuer.public_key, c.tbs, c.signature) catch |err| return switch (err) {
        error.BadSignature => error.UnauthorizedResponder,
        else => err,
    };
}

/// Checks that `response` (a DER OCSPResponse) may be stapled for `chain`
/// (DER certificates, leaf first, its issuer among the rest) at `now`
/// (seconds since the epoch).
pub fn check(response: []const u8, chain: []const []const u8, now: i64) Error!Checked {
    return evaluate(try verify(response, chain), now);
}

/// Everything about `response` that doesn't depend on the time: it parses
/// (strict DER throughout), is successful and basic, has a SHA-1 CertID
/// for the leaf (the first decides; every SingleResponse must parse), and
/// is properly signed (`checkSigner`).
pub fn verify(response: []const u8, chain: []const []const u8) Error!Verified {
    if (response.len > max_response_len) return error.TooLarge;
    var top: Der = .{ .bytes = response };
    var resp: Der = .{ .bytes = try top.expect(tag.sequence) };
    try top.end();
    const status = try resp.expect(tag.enumerated);
    if (status.len != 1) return error.Malformed;
    if (status[0] != 0) {
        // malformedRequest (1) to unauthorized (6), without responseBytes.
        try resp.end();
        return error.NotSuccessful;
    }
    var bytes_explicit: Der = .{ .bytes = try resp.expect(tag.ctx0) };
    try resp.end();
    var rb: Der = .{ .bytes = try bytes_explicit.expect(tag.sequence) };
    try bytes_explicit.end();
    const response_type = try rb.expect(tag.oid);
    const basic_der = try rb.expect(tag.octet_string);
    try rb.end();
    if (!eql(response_type, &oid_ocsp_basic)) return error.NotBasic;

    // BasicOCSPResponse (§4.2.1).
    var basic_outer: Der = .{ .bytes = basic_der };
    var basic: Der = .{ .bytes = try basic_outer.expect(tag.sequence) };
    try basic_outer.end();
    const tbs = try basic.expectElement(tag.sequence);
    const sig_alg = try basic.expect(tag.sequence);
    const signature = try bitString(try basic.expect(tag.bit_string));
    const certs = try basic.optional(tag.ctx0);
    if (certs) |list| try checkCerts(list);
    try basic.end();

    // ResponseData.
    var data: Der = .{ .bytes = tbs.contents };
    if (try data.optional(tag.ctx0)) |v| {
        // Version: only v1 (0) exists (and DER would leave it out).
        var vd: Der = .{ .bytes = v };
        const ver = try vd.expect(tag.integer);
        try vd.end();
        if (ver.len != 1 or ver[0] != 0) return error.Malformed;
    }
    const responder = try data.next(); // byName [1] or byKey [2]
    if (responder.tag != tag.ctx1 and responder.tag != tag.ctx2) return error.Malformed;
    const produced_at = try parseTime(try data.expect(tag.generalized_time));
    var responses: Der = .{ .bytes = try data.expect(tag.sequence) };
    if (try data.optional(tag.ctx1)) |exts| try checkExtensions(exts);
    try data.end();

    const subject = try Subject.init(chain);
    var found: ?struct { status: Status, this_update: i64, next_update: ?i64, issuer: *const Cert } = null;
    var sha2_only = false;
    var first_id: ?CertId = null;
    var several_issuers = false;
    if (responses.atEnd()) return error.Malformed;
    while (!responses.atEnd()) {
        var single: Der = .{ .bytes = try responses.expect(tag.sequence) };
        const cert_id = try CertId.parse(try single.expect(tag.sequence));
        if (first_id) |f| {
            if (!f.sameIssuer(cert_id)) several_issuers = true;
        } else first_id = cert_id;
        // CertStatus: good [0] IMPLICIT NULL, revoked [1] IMPLICIT
        // RevokedInfo, unknown [2] IMPLICIT NULL.
        const cert_status = try single.next();
        const st: Status = switch (cert_status.tag) {
            tag.good, tag.unknown => blk: {
                if (cert_status.contents.len != 0) return error.Malformed;
                break :blk if (cert_status.tag == tag.good) .good else .unknown;
            },
            tag.ctx1 => blk: {
                var revoked: Der = .{ .bytes = cert_status.contents };
                _ = try parseTime(try revoked.expect(tag.generalized_time));
                _ = try revoked.optional(tag.ctx0); // revocationReason
                try revoked.end();
                break :blk .revoked;
            },
            else => return error.Malformed,
        };
        const this_update = try parseTime(try single.expect(tag.generalized_time));
        var next_update: ?i64 = null;
        if (try single.optional(tag.ctx0)) |n| {
            var nd: Der = .{ .bytes = n };
            next_update = try parseTime(try nd.expect(tag.generalized_time));
            try nd.end();
            if (next_update.? < this_update) return error.Malformed;
        }
        if (try single.optional(tag.ctx1)) |exts| try checkExtensions(exts);
        try single.end();
        if (found == null) {
            if (cert_id.issuer(&subject)) |m| {
                if (m.sha1) {
                    found = .{ .status = st, .this_update = this_update, .next_update = next_update, .issuer = m.cert };
                } else sha2_only = true;
            }
        }
    }
    const f = found orelse return if (sha2_only) error.NoSha1CertId else error.NotForCertificate;
    const validity = try checkSigner(&subject, f.issuer, responder, sig_alg, tbs.all, signature, certs, several_issuers);
    return .{
        .status = f.status,
        .this_update = f.this_update,
        .next_update = f.next_update,
        .produced_at = produced_at,
        .signer_not_before = validity[0],
        .signer_not_after = validity[1],
    };
}

/// What time decides about a verified response at `now`: the delegated
/// responder's certificate is valid, nextUpdate (or a day after
/// thisUpdate) hasn't passed, thisUpdate and producedAt aren't more than
/// `max_clock_skew_s` ahead; then that the certificate is good. Current
/// before what it says: a stale revocation is no news.
pub fn evaluate(v: Verified, now: i64) Error!Checked {
    if (now < v.signer_not_before or now > v.signer_not_after) return error.ResponderNotCurrent;
    const expires = @min(v.next_update orelse v.this_update + default_validity_s, v.signer_not_after +| 1);
    if (now >= expires) return error.Expired;
    if (v.this_update > now + max_clock_skew_s or v.produced_at > now + max_clock_skew_s) return error.NotYetValid;
    switch (v.status) {
        .good => {},
        .revoked => return error.Revoked,
        .unknown => return error.StatusUnknown,
    }
    return .{ .this_update = v.this_update, .expires = expires };
}

/// A certificate's validity time (RFC 5280 §4.1.2.5): UTCTime
/// (YYMMDDHHMMSSZ, years 1950-2049) or GeneralizedTime.
fn parseCertTime(e: Der.Element) Error!i64 {
    switch (e.tag) {
        tag.generalized_time => return parseTime(e.contents),
        tag.utc_time => {
            const s = e.contents;
            if (s.len != 13 or s[0] < '0' or s[0] > '9' or s[1] < '0' or s[1] > '9') return error.Malformed;
            var buf: [15]u8 = undefined;
            const century: []const u8 = if (s[0] < '5') "20" else "19";
            @memcpy(buf[0..2], century);
            @memcpy(buf[2..], s);
            return parseTime(&buf);
        },
        else => return error.Malformed,
    }
}

/// GeneralizedTime as DER has it (RFC 5280 §4.1.2.5.2, RFC 6960):
/// YYYYMMDDHHMMSS, optional fractional seconds, then Z. Seconds since the
/// epoch.
fn parseTime(s: []const u8) Error!i64 {
    if (s.len < 15 or s[s.len - 1] != 'Z') return error.Malformed;
    for (s[0..14]) |c| if (c < '0' or c > '9') return error.Malformed;
    if (s.len > 15) {
        // ".d...d": at least one digit (DER: no trailing zero).
        const frac = s[14 .. s.len - 1];
        if (frac.len < 2 or frac[0] != '.' or frac[frac.len - 1] == '0') return error.Malformed;
        for (frac[1..]) |c| if (c < '0' or c > '9') return error.Malformed;
    }
    const num = struct {
        fn f(d: []const u8) u32 {
            var v: u32 = 0;
            for (d) |c| v = v * 10 + (c - '0');
            return v;
        }
    }.f;
    const year = num(s[0..4]);
    const month = num(s[4..6]);
    const day = num(s[6..8]);
    const hour = num(s[8..10]);
    const minute = num(s[10..12]);
    const second = num(s[12..14]);
    if (month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59 or second > 59) return error.Malformed;
    const leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
    const month_days = [_]u32{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (day > month_days[month - 1]) return error.Malformed;
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil).
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = (month + 9) % 12;
    const doy = @divFloor(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

/// The leaf CertificateEntry's extensions for `response` (RFC 8446
/// §4.4.2.1): status_request with a CertificateStatus (RFC 6066 §8) of
/// type ocsp. `out` needs `entryLen(response.len)` bytes.
pub fn writeEntryExtensions(out: []u8, response: []const u8) []const u8 {
    std.debug.assert(response.len <= max_response_len);
    const n = entryLen(response.len);
    std.mem.writeInt(u16, out[0..2], @backingInt(ExtensionType.status_request), .big);
    std.mem.writeInt(u16, out[2..4], @intCast(n - 4), .big);
    out[4] = 1; // status_type: ocsp
    std.mem.writeInt(u24, out[5..8], @intCast(response.len), .big);
    @memcpy(out[8..n], response);
    return out[0..n];
}

pub fn entryLen(response_len: usize) usize {
    return 8 + response_len;
}

/// One certificate's OCSP response, shared by every worker's handshakes
/// and replaced from another thread (see `src/ocsp_watcher.zig`).
///
/// Two slots: handshakes read the current one (`acquire`, `Ref.release`)
/// while a new response is written into the other, which becomes current
/// once complete. A reader counts itself in a slot, then checks the slot
/// is still current (if not, it backs off and tries again); a writer waits
/// until nobody is counted in the slot it is about to overwrite. Both
/// steps are sequentially consistent, so either the writer sees the
/// reader's count or the reader sees the slot is no longer current. Readers
/// never wait or allocate; the bytes are copied into the handshake's
/// flight between `acquire` and `release`.
pub const Staple = struct {
    const none = 2;

    allocator: std.mem.Allocator,
    /// The clock (tests set a fixed one).
    now: *const fn () i64 = sys.realtimeSeconds,
    slots: [2]Slot = .{ .{}, .{} },
    /// The slot readers take; `none` without a response.
    current: std.atomic.Value(u8) = .init(none),
    /// Serialises writers.
    writer: sys.Mutex = .{},

    const Slot = struct {
        readers: std.atomic.Value(u32) = .init(0),
        /// The CertificateEntry extensions (`writeEntryExtensions`), in a
        /// buffer of `cap` bytes.
        buf: [*]u8 = undefined,
        cap: usize = 0,
        len: usize = 0,
        expires: i64 = 0,
    };

    pub const Ref = struct {
        slot: *Slot,
        /// The leaf CertificateEntry's extensions.
        bytes: []const u8,

        pub fn release(self: Ref) void {
            _ = self.slot.readers.fetchSub(1, .release);
        }
    };

    pub fn init(allocator: std.mem.Allocator) Staple {
        return .{ .allocator = allocator };
    }

    /// No reader may be left.
    pub fn deinit(self: *Staple) void {
        for (&self.slots) |*s| {
            std.debug.assert(s.readers.load(.monotonic) == 0);
            if (s.cap > 0) self.allocator.free(s.buf[0..s.cap]);
        }
    }

    /// The current response unless it has expired; `Ref.release` when
    /// done with it.
    pub fn acquire(self: *Staple) ?Ref {
        while (true) {
            const i = self.current.load(.seq_cst);
            if (i == none) return null;
            const slot = &self.slots[i];
            _ = slot.readers.fetchAdd(1, .seq_cst);
            if (self.current.load(.seq_cst) != i) {
                _ = slot.readers.fetchSub(1, .release);
                continue;
            }
            const ref: Ref = .{ .slot = slot, .bytes = slot.buf[0..slot.len] };
            if (self.now() >= slot.expires) {
                ref.release();
                return null;
            }
            return ref;
        }
    }

    /// Staples `response` (checked: see `check`) until `expires`.
    /// Thread-safe; waits only for handshakes reading the slot it
    /// replaces.
    pub fn set(self: *Staple, response: []const u8, expires: i64) error{ OutOfMemory, TooLarge }!void {
        if (response.len > max_response_len) return error.TooLarge;
        self.writer.lock();
        defer self.writer.unlock();
        const cur = self.current.load(.seq_cst);
        const j: u8 = if (cur == 0) 1 else 0;
        const slot = &self.slots[j];
        while (slot.readers.load(.seq_cst) != 0) std.Thread.yield() catch {};
        const n = entryLen(response.len);
        if (slot.cap < n) {
            const buf = try self.allocator.alloc(u8, n);
            if (slot.cap > 0) self.allocator.free(slot.buf[0..slot.cap]);
            slot.buf = buf.ptr;
            slot.cap = n;
        }
        slot.len = writeEntryExtensions(slot.buf[0..n], response).len;
        slot.expires = expires;
        self.current.store(j, .seq_cst);
    }

    /// Stops stapling.
    pub fn clear(self: *Staple) void {
        self.writer.lock();
        defer self.writer.unlock();
        self.current.store(none, .seq_cst);
    }

    /// When the current response expires; null without one.
    pub fn expiry(self: *Staple) ?i64 {
        self.writer.lock();
        defer self.writer.unlock();
        const i = self.current.load(.seq_cst);
        return if (i == none) null else self.slots[i].expires;
    }
};

// -- Tests ------------------------------------------------------------

pub const testdata = struct {
    pub const ca_cert = @embedFile("testdata/ocsp/ca.pem");
    pub const ca_key = @embedFile("testdata/ocsp/ca.key");
    /// localhost and 127.0.0.1, serial 0x1001; with the CA.
    pub const leaf_chain = @embedFile("testdata/ocsp/leaf-chain.pem");
    pub const leaf_cert = @embedFile("testdata/ocsp/leaf.pem");
    pub const leaf_key = @embedFile("testdata/ocsp/leaf.key");
    /// ocsp.example, serial 0x1002; with the CA.
    pub const sni_chain = @embedFile("testdata/ocsp/sni-chain.pem");
    pub const sni_key = @embedFile("testdata/ocsp/sni.key");
    /// See testdata/ocsp/gen.sh for what each one is.
    pub const leaf_good = @embedFile("testdata/ocsp/leaf-good.der");
    pub const leaf_good_sha256 = @embedFile("testdata/ocsp/leaf-good-sha256.der");
    pub const leaf_good_ca384 = @embedFile("testdata/ocsp/leaf-good-ca384.der");
    pub const leaf_good_rsa = @embedFile("testdata/ocsp/leaf-good-rsa.der");
    pub const leaf_good_rsa512 = @embedFile("testdata/ocsp/leaf-good-rsa512.der");
    pub const leaf_good_pss = @embedFile("testdata/ocsp/leaf-good-pss.der");
    pub const leaf_good_p384 = @embedFile("testdata/ocsp/leaf-good-p384.der");
    pub const leaf_good_ed25519 = @embedFile("testdata/ocsp/leaf-good-ed25519.der");
    pub const leaf_good_shortlived = @embedFile("testdata/ocsp/leaf-good-shortlived.der");
    pub const leaf_good_noeku = @embedFile("testdata/ocsp/leaf-good-noeku.der");
    pub const leaf_good_rogue = @embedFile("testdata/ocsp/leaf-good-rogue.der");
    pub const leaf_good_nocert = @embedFile("testdata/ocsp/leaf-good-nocert.der");
    pub const leaf_good_forged = @embedFile("testdata/ocsp/leaf-good-forged.der");
    pub const leaf_good_renamed = @embedFile("testdata/ocsp/leaf-good-renamed.der");
    pub const leaf_revoked = @embedFile("testdata/ocsp/leaf-revoked.der");
    pub const leaf_unknown = @embedFile("testdata/ocsp/leaf-unknown.der");
    pub const sni_good = @embedFile("testdata/ocsp/sni-good.der");
    pub const both_good = @embedFile("testdata/ocsp/both-good.der");
    pub const short = @embedFile("testdata/ocsp/short.der");
    /// thisUpdate (and producedAt) of leaf-good.der, 2026-10-31 18:25:06
    /// UTC; the others were made within seconds after it. nextUpdate is
    /// 36500 days after thisUpdate, or (short) 60 s after.
    pub const this_update: i64 = 1793471106;
    pub const next_update: i64 = this_update + validity_s;
    pub const validity_s: i64 = 36500 * 86400;
};

const testing = std.testing;
const Credentials = @import("./credentials.zig").Credentials;

fn testChains() !struct { leaf: Credentials, sni: Credentials } {
    var leaf = try Credentials.fromPem(testing.allocator, testdata.leaf_chain, testdata.leaf_key);
    errdefer leaf.deinit();
    const sni = try Credentials.fromPem(testing.allocator, testdata.sni_chain, testdata.sni_key);
    return .{ .leaf = leaf, .sni = sni };
}

/// A response made by gen.sh: thisUpdate seconds after leaf-good.der's,
/// valid for 100 years.
fn expectHundredYears(c: Checked) !void {
    try testing.expect(c.this_update >= testdata.this_update and c.this_update < testdata.this_update + 60);
    try testing.expectEqual(testdata.validity_s, c.expires - c.this_update);
}

test "parseTime: GeneralizedTime to seconds, strictly" {
    try testing.expectEqual(@as(i64, 0), try parseTime("19700101000000Z"));
    try testing.expectEqual(testdata.this_update, try parseTime("20261031182506Z"));
    try testing.expectEqual(@as(i64, 951782400), try parseTime("20000229000000Z"));
    try testing.expectEqual(@as(i64, 4107542399), try parseTime("21000228235959Z"));
    try testing.expectEqual(@as(i64, -2208988800), try parseTime("19000101000000Z"));
    try testing.expectEqual(testdata.this_update, try parseTime("20261031182506.25Z"));
    for ([_][]const u8{
        "",                "2026103117035Z",  "20261031170359",   "20261031170359+0100", "2026103117035aZ",
        "20261331170359Z", "20261000170359Z", "20261032170359Z",  "21000229000000Z",     "20261031240000Z",
        "20261031176000Z", "20261031170360Z", "20261031170359.Z", "20261031170359.50Z",  "20261031170359,5Z",
    }) |bad| try testing.expectError(error.Malformed, parseTime(bad));
    // UTCTime in certificates: 1950 to 2049.
    try testing.expectEqual(testdata.this_update, try parseCertTime(.{ .tag = tag.utc_time, .contents = "261031182506Z", .all = "" }));
    try testing.expectEqual(@as(i64, -631152000), try parseCertTime(.{ .tag = tag.utc_time, .contents = "500101000000Z", .all = "" }));
    try testing.expectError(error.Malformed, parseCertTime(.{ .tag = tag.utc_time, .contents = "2610311810Z", .all = "" }));
    try testing.expectError(error.Malformed, parseCertTime(.{ .tag = tag.integer, .contents = "261031181039Z", .all = "" }));
}

test "check: the test responses" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    try testing.expectEqual(Checked{ .this_update = testdata.this_update, .expires = testdata.next_update }, try check(testdata.leaf_good, c.leaf.chain, now));
    for ([_][]const u8{ testdata.leaf_good_ca384, testdata.both_good }) |r| try expectHundredYears(try check(r, c.leaf.chain, now));
    // A SHA-256 CertID only: OpenSSL clients look up a SHA-1 one.
    try testing.expectError(error.NoSha1CertId, check(testdata.leaf_good_sha256, c.leaf.chain, now));
    // Several SingleResponses: the one for the certificate.
    for ([_][]const u8{ testdata.sni_good, testdata.both_good }) |r| try expectHundredYears(try check(r, c.sni.chain, now));
    // Another certificate's.
    try testing.expectError(error.NotForCertificate, check(testdata.sni_good, c.leaf.chain, now));
    try testing.expectError(error.NotForCertificate, check(testdata.leaf_good, c.sni.chain, now));
    try testing.expectError(error.Revoked, check(testdata.leaf_revoked, c.leaf.chain, now));
    // A revocation that is out of date isn't news (it doesn't stop
    // stapling: see the watcher); one from the future isn't either.
    try testing.expectError(error.Expired, check(testdata.leaf_revoked, c.leaf.chain, testdata.next_update + 1));
    try testing.expectError(error.NotYetValid, check(testdata.leaf_revoked, c.leaf.chain, testdata.this_update - 86400));
    try testing.expectError(error.StatusUnknown, check(testdata.leaf_unknown, c.leaf.chain, now));
    // nextUpdate: stapled up to the second before.
    const short = try check(testdata.short, c.leaf.chain, testdata.this_update + 1);
    try testing.expectEqual(short.this_update + 60, short.expires);
    _ = try check(testdata.short, c.leaf.chain, short.expires - 1);
    try testing.expectError(error.Expired, check(testdata.short, c.leaf.chain, short.expires));
    try testing.expectError(error.Expired, check(testdata.leaf_good, c.leaf.chain, testdata.next_update));
    // Without the issuer in the chain the CertID can't be checked.
    try testing.expectError(error.NoIssuer, check(testdata.leaf_good, c.leaf.chain[0..1], now));
    try testing.expectError(error.NoIssuer, check(testdata.leaf_good, &.{}, now));
    // Unsuccessful responses (malformedRequest .. unauthorized).
    for ([_]u8{ 1, 2, 3, 5, 6 }) |s| {
        try testing.expectError(error.NotSuccessful, check(&.{ 0x30, 0x03, 0x0a, 0x01, s }, c.leaf.chain, now));
    }
    try testing.expectError(error.Malformed, check(&.{ 0x30, 0x03, 0x0a, 0x01, 0x00 }, c.leaf.chain, now));
}

test "check: thisUpdate and producedAt at most 300 s ahead of the clock" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const t = testdata.this_update;
    _ = try check(testdata.leaf_good, c.leaf.chain, t - max_clock_skew_s);
    try testing.expectError(error.NotYetValid, check(testdata.leaf_good, c.leaf.chain, t - max_clock_skew_s - 1));
    try testing.expectError(error.NotYetValid, check(testdata.leaf_good, c.leaf.chain, t - 86400));
}

test "check: the responder's signature: the issuer, or a responder it delegated to, every supported algorithm" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const td = testdata;
    const now = td.this_update + 3600;
    // The CA (P-256 with SHA-256 or SHA-384); delegated responders with
    // RSA PKCS#1 v1.5 (SHA-256, SHA-512), RSA-PSS, P-384 and Ed25519.
    for ([_][]const u8{ td.leaf_good_ca384, td.leaf_good_rsa, td.leaf_good_rsa512, td.leaf_good_pss, td.leaf_good_p384, td.leaf_good_ed25519 }) |r| {
        try expectHundredYears(try check(r, c.leaf.chain, now));
    }
    // A responder certificate valid for a day: its response is stapled
    // until the certificate's notAfter, not for its 100-year nextUpdate.
    const short = try check(td.leaf_good_shortlived, c.leaf.chain, now);
    try testing.expect(short.expires > now and short.expires <= td.this_update + 86400 + 60);
    // A responder certificate without id-kp-OCSPSigning, or left out.
    try testing.expectError(error.UnauthorizedResponder, check(td.leaf_good_noeku, c.leaf.chain, now));
    try testing.expectError(error.UnauthorizedResponder, check(td.leaf_good_nocert, c.leaf.chain, now));
    // One with id-kp-OCSPSigning in the CA's name, but not signed by it.
    try testing.expectError(error.UnauthorizedResponder, check(td.leaf_good_forged, c.leaf.chain, now));
    // One signed with the CA's key but in another issuer name.
    try testing.expectError(error.UnauthorizedResponder, check(td.leaf_good_renamed, c.leaf.chain, now));
    // A self-signed one named like the CA: the CA's key doesn't verify it.
    try testing.expectError(error.BadSignature, check(td.leaf_good_rogue, c.leaf.chain, now));
    // A responder certificate past its notAfter (it was valid for a day),
    // or before its notBefore by more than the skew allowed.
    try testing.expectError(error.ResponderNotCurrent, check(td.leaf_good_shortlived, c.leaf.chain, td.this_update + 2 * 86400));
    try testing.expectError(error.ResponderNotCurrent, check(td.leaf_good_shortlived, c.leaf.chain, td.this_update - 2 * max_clock_skew_s));
    // Even a little before its notBefore: OpenSSL allows no skew there.
    try testing.expectError(error.ResponderNotCurrent, check(td.leaf_good_shortlived, c.leaf.chain, td.this_update - max_clock_skew_s / 2));
}

/// Where `part` (a slice of `whole`) starts and ends in it.
fn rangeIn(whole: []const u8, part: []const u8) [2]usize {
    const at = @intFromPtr(part.ptr) - @intFromPtr(whole.ptr);
    return .{ at, at + part.len };
}

/// The signed ResponseData, the signature and the certificates of a
/// basic response, as ranges of it.
fn basicRanges(response: []const u8) ![3][2]usize {
    var top: Der = .{ .bytes = response };
    var resp: Der = .{ .bytes = try top.expect(tag.sequence) };
    _ = try resp.expect(tag.enumerated);
    var bytes_explicit: Der = .{ .bytes = try resp.expect(tag.ctx0) };
    var rb: Der = .{ .bytes = try bytes_explicit.expect(tag.sequence) };
    _ = try rb.expect(tag.oid);
    var basic_outer: Der = .{ .bytes = try rb.expect(tag.octet_string) };
    var basic: Der = .{ .bytes = try basic_outer.expect(tag.sequence) };
    const tbs = try basic.expectElement(tag.sequence);
    _ = try basic.expect(tag.sequence);
    const sig = try basic.expectElement(tag.bit_string);
    const certs = try basic.expectElement(tag.ctx0);
    return .{ rangeIn(response, tbs.all), rangeIn(response, sig.all), rangeIn(response, certs.contents) };
}

test "check: every truncation fails; every bit flip in what is signed or in the signature fails" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    for ([_][]const u8{ testdata.leaf_good, testdata.leaf_good_rsa }) |good| {
        for (0..good.len) |n| {
            try testing.expect(std.meta.isError(check(good[0..n], c.leaf.chain, now)));
        }
        // A trailing byte, at each level the parser checks the end of.
        var buf: [4096]u8 = undefined;
        @memcpy(buf[0..good.len], good);
        buf[good.len] = 0;
        try testing.expectError(error.Malformed, check(buf[0 .. good.len + 1], c.leaf.chain, now));
        // A flipped bit fails unless it is inside the certificates
        // (only the responder's is looked at, and leaf-good.der's is the
        // CA's own, matched in the chain; leaf-good-rsa.der's responder
        // certificate is signed by the CA).
        const r = try basicRanges(good);
        var accepted: usize = 0;
        for (0..good.len) |at| {
            for (0..8) |bit| {
                const p = patched(&buf, good, at, good[at] ^ (@as(u8, 1) << @intCast(bit)));
                if (check(p, c.leaf.chain, now)) |_| {
                    accepted += 1;
                    try testing.expect(at >= r[2][0] and at < r[2][1]);
                } else |_| {}
                if (at >= r[0][0] and at < r[1][1]) try testing.expect(std.meta.isError(check(p, c.leaf.chain, now)));
            }
        }
        if (good.ptr == testdata.leaf_good.ptr) try testing.expect(accepted > 0) else try testing.expectEqual(0, accepted);
    }
}

/// `good` with the byte at `at` replaced by `b`.
fn patched(buf: []u8, good: []const u8, at: usize, b: u8) []const u8 {
    @memcpy(buf[0..good.len], good);
    buf[at] = b;
    return buf[0..good.len];
}

test "check: a SHA-1 CertID with each field wrong" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    const good = testdata.leaf_good;
    // The CertID: SEQUENCE { AlgorithmIdentifier, OCTET STRING (20),
    // OCTET STRING (20), INTEGER 0x1001 }.
    const at = std.mem.indexOf(u8, good, &.{ 0x04, 0x14 }).?;
    const name_hash = at + 2;
    const key_hash = std.mem.indexOfPos(u8, good, name_hash + 20, &.{ 0x04, 0x14 }).? + 2;
    const serial = std.mem.indexOfPos(u8, good, key_hash + 20, &.{ 0x02, 0x02, 0x10, 0x01 }).? + 2;
    var buf: [1024]u8 = undefined;
    for ([_]usize{ name_hash, name_hash + 19, key_hash, key_hash + 19, serial, serial + 1 }) |pos| {
        try testing.expectError(error.NotForCertificate, check(patched(&buf, good, pos, good[pos] ^ 1), c.leaf.chain, now));
    }
}

test "check: DER lengths must be minimal and inside their parent" {
    // A length in long form that fits in short form, a leading zero length
    // byte, the indefinite length and a length past the end.
    for ([_][]const u8{
        &.{ 0x30, 0x81, 0x03, 0x0a, 0x01, 0x01 },
        &.{ 0x30, 0x82, 0x00, 0x03, 0x0a, 0x01, 0x01 },
        &.{ 0x30, 0x80, 0x0a, 0x01, 0x01, 0x00, 0x00 },
        &.{ 0x30, 0x04, 0x0a, 0x01, 0x01 },
        &.{ 0x30, 0x03, 0x0a, 0x02, 0x01 },
        &.{ 0x3f, 0x03, 0x0a, 0x01, 0x01 },
    }) |bad| try testing.expectError(error.Malformed, check(bad, &.{}, 0));
    try testing.expectError(error.NotSuccessful, check(&.{ 0x30, 0x03, 0x0a, 0x01, 0x01 }, &.{}, 0));
}

test "max_response_len: the largest response still fits CertificateEntry.extensions" {
    // The extension (type, length, status_type, 24-bit length and the
    // response) must fit the entry's 16-bit extensions length.
    try testing.expectEqual(@as(usize, 0xffff), entryLen(max_response_len));
    var big: [max_response_len + 1]u8 = undefined;
    try testing.expectError(error.TooLarge, check(&big, &.{}, 0));
    var s: Staple = .init(testing.allocator);
    defer s.deinit();
    s.now = stapleTestClock;
    staple_test_now = 0;
    try testing.expectError(error.TooLarge, s.set(&big, 1));
    try s.set(big[0..max_response_len], 1);
    const r = s.acquire().?;
    defer r.release();
    try testing.expectEqual(@as(usize, 0xffff), r.bytes.len);
}

test "writeEntryExtensions: status_request with an ocsp CertificateStatus" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0, 5, 0, 7, 1, 0, 0, 3, 'a', 'b', 'c' }, writeEntryExtensions(&buf, "abc"));
}

var staple_test_now: i64 = 1000;
fn stapleTestClock() i64 {
    return staple_test_now;
}

test "Staple: set, replace, expire, clear" {
    var s: Staple = .init(testing.allocator);
    defer s.deinit();
    s.now = stapleTestClock;
    staple_test_now = 1000;
    try testing.expectEqual(null, s.acquire());
    try s.set("first", 2000);
    {
        const r = s.acquire().?;
        defer r.release();
        try testing.expectEqualSlices(u8, "\x00\x05\x00\x09\x01\x00\x00\x05first", r.bytes);
    }
    // A longer one grows the other slot; a shorter one reuses the first.
    try s.set("second response", 3000);
    try s.set("third", 4000);
    {
        const r = s.acquire().?;
        defer r.release();
        try testing.expectEqualStrings("third", r.bytes[8..]);
    }
    try testing.expectEqual(@as(?i64, 4000), s.expiry());
    staple_test_now = 4000;
    try testing.expectEqual(null, s.acquire());
    staple_test_now = 3999;
    s.acquire().?.release();
    s.clear();
    try testing.expectEqual(null, s.acquire());
    try testing.expectEqual(null, s.expiry());
    var big: [max_response_len + 1]u8 = undefined;
    try testing.expectError(error.TooLarge, s.set(&big, 5000));
}

test "Staple: readers on other threads always see one whole response while it is replaced" {
    var s: Staple = .init(testing.allocator);
    defer s.deinit();
    s.now = stapleTestClock;
    staple_test_now = 0;
    // Response k: k + 1 bytes, each k.
    var resp: [256]u8 = undefined;
    @memset(resp[0..1], 0);
    try s.set(resp[0..1], 1);
    const Reader = struct {
        fn run(st: *Staple, stop: *std.atomic.Value(bool), bad: *std.atomic.Value(u32), reads: *std.atomic.Value(u32)) void {
            while (!stop.load(.acquire)) {
                const r = st.acquire() orelse continue;
                const body = r.bytes[8..];
                const k = body[0];
                if (body.len != @as(usize, k) + 1) _ = bad.fetchAdd(1, .monotonic);
                for (body) |b| if (b != k) {
                    _ = bad.fetchAdd(1, .monotonic);
                    break;
                };
                r.release();
                _ = reads.fetchAdd(1, .monotonic);
            }
        }
    };
    var stop: std.atomic.Value(bool) = .init(false);
    var bad: std.atomic.Value(u32) = .init(0);
    var reads: std.atomic.Value(u32) = .init(0);
    var threads: [3]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Reader.run, .{ &s, &stop, &bad, &reads });
    var k: usize = 0;
    while (k < 20000 or reads.load(.monotonic) < 20000) : (k += 1) {
        const v: u8 = @truncate(k);
        @memset(resp[0 .. @as(usize, v) + 1], v);
        try s.set(resp[0 .. @as(usize, v) + 1], 1);
    }
    stop.store(true, .release);
    for (threads) |t| t.join();
    try testing.expectEqual(@as(u32, 0), bad.load(.monotonic));
}

fn fuzzCheck(chains: *const [2][]const []const u8, smith: *std.testing.Smith) anyerror!void {
    // Room for every size up to one byte past the largest stapled.
    var buf: [max_response_len + 1]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];
    const now = testdata.this_update + 3600;
    for (chains) |chain| {
        const result = check(input, chain, now);
        // The same answer twice; an accepted response is good, fresh and
        // signed (so mutants rarely pass), and none of its proper prefixes
        // is accepted (DER lengths are exact).
        try testing.expectEqual(result, check(input, chain, now));
        const ok = result catch continue;
        try testing.expect(ok.expires > now and ok.this_update <= ok.expires);
        try testing.expect(std.meta.isError(check(input[0 .. input.len - 1], chain, now)));
        var ext: [entryLen(max_response_len)]u8 = undefined;
        const e = writeEntryExtensions(&ext, input);
        try testing.expectEqual(input.len + 4, std.mem.readInt(u16, e[2..4], .big));
    }
}

test "fuzz: ocsp response check" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const chains: [2][]const []const u8 = .{ c.leaf.chain, c.sni.chain };
    // The largest response, and one byte more (padded certificates).
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const largest = try craft.padded(arena.allocator(), testdata.leaf_good, max_response_len);
    const too_large = try craft.padded(arena.allocator(), testdata.leaf_good, max_response_len + 1);
    try std.testing.fuzz(&chains, fuzzCheck, .{ .corpus = &.{
        largest,
        too_large,
        testdata.leaf_good,
        testdata.leaf_good_sha256,
        testdata.leaf_revoked,
        testdata.leaf_unknown,
        testdata.sni_good,
        testdata.both_good,
        testdata.short,
        testdata.leaf_good_ca384,
        testdata.leaf_good_rsa,
        testdata.leaf_good_pss,
        testdata.leaf_good_p384,
        testdata.leaf_good_ed25519,
        testdata.leaf_good_noeku,
        testdata.leaf_good_rogue,
        testdata.leaf_good_forged,
        &.{ 0x30, 0x03, 0x0a, 0x01, 0x06 },
    } });
}

// -- Adversarial verification -------------------------------------------

/// Builds responses by hand from the test ones, signed again by the test
/// CA (ECDSA P-256 with SHA-256).
pub const craft = struct {
    fn lenLen(n: usize) usize {
        return if (n < 0x80) 1 else if (n < 0x100) 2 else if (n < 0x10000) 3 else 4;
    }

    /// The size of an element with `n` bytes of contents.
    pub fn elemLen(n: usize) usize {
        return 1 + lenLen(n) + n;
    }

    /// Tag, DER length and the concatenation of `parts`.
    pub fn tlv(a: std.mem.Allocator, t: u8, parts: []const []const u8) ![]u8 {
        var n: usize = 0;
        for (parts) |p| n += p.len;
        const out = try a.alloc(u8, elemLen(n));
        out[0] = t;
        var i: usize = 1;
        switch (lenLen(n)) {
            1 => out[1] = @intCast(n),
            else => |l| {
                out[1] = @intCast(0x80 | (l - 1));
                var k: usize = l - 1;
                while (k > 0) : (k -= 1) out[1 + k] = @truncate(n >> @intCast(8 * (l - 1 - k)));
            },
        }
        i += lenLen(n);
        for (parts) |p| {
            @memcpy(out[i..][0..p.len], p);
            i += p.len;
        }
        return out;
    }

    /// The pieces of a test response.
    pub const Parts = struct {
        /// ResponseData's elements before `responses` (version,
        /// responderID, producedAt), whole.
        data_head: []const u8,
        /// Each SingleResponse, whole.
        singles: [8][]const u8 = undefined,
        single_count: usize = 0,
        /// responseExtensions, whole, or "".
        data_exts: []const u8 = "",
        sig_alg: []const u8,
        signature: []const u8,
        /// certs [0], whole, or "".
        certs: []const u8 = "",
    };

    pub fn split(resp: []const u8) !Parts {
        var top: Der = .{ .bytes = resp };
        var r: Der = .{ .bytes = try top.expect(tag.sequence) };
        _ = try r.expect(tag.enumerated);
        var e: Der = .{ .bytes = try r.expect(tag.ctx0) };
        var rb: Der = .{ .bytes = try e.expect(tag.sequence) };
        _ = try rb.expect(tag.oid);
        var bo: Der = .{ .bytes = try rb.expect(tag.octet_string) };
        var basic: Der = .{ .bytes = try bo.expect(tag.sequence) };
        const data_el = try basic.next();
        const alg = try basic.next();
        const sig = try basic.next();
        const certs = if (basic.atEnd()) "" else (try basic.next()).all;
        var data: Der = .{ .bytes = data_el.contents };
        const head_start = data.pos;
        while (data.peekTag() != tag.sequence) _ = try data.next();
        const head = data.bytes[head_start..data.pos];
        var responses: Der = .{ .bytes = try data.expect(tag.sequence) };
        var p: Parts = .{ .data_head = head, .sig_alg = alg.all, .signature = sig.all, .certs = certs };
        while (!responses.atEnd()) {
            p.singles[p.single_count] = (try responses.next()).all;
            p.single_count += 1;
        }
        if (!data.atEnd()) p.data_exts = (try data.next()).all;
        return p;
    }

    /// A whole OCSPResponse from `p`, with `singles` as its responses and
    /// `certs` (whole) as the certs field, signed by the test CA.
    pub fn join(a: std.mem.Allocator, p: Parts, singles: []const []const u8, certs: []const u8) ![]u8 {
        const responses = try tlv(a, tag.sequence, singles);
        const data = try tlv(a, tag.sequence, &.{ p.data_head, responses, p.data_exts });
        const ca = try @import("./credentials.zig").Credentials.fromPem(a, testdata.ca_cert, testdata.ca_key);
        var sig_buf: [@import("./credentials.zig").max_signature_len]u8 = undefined;
        const sig = try ca.key.sign(data, @splat(7), &sig_buf);
        const signature = try tlv(a, tag.bit_string, &.{ &.{0}, sig });
        const sig_alg = try tlv(a, tag.sequence, &.{&([_]u8{ tag.oid, oid_ecdsa_sha256.len } ++ oid_ecdsa_sha256)});
        const basic = try tlv(a, tag.sequence, &.{ data, sig_alg, signature, certs });
        const octets = try tlv(a, tag.octet_string, &.{basic});
        const rb = try tlv(a, tag.sequence, &.{ &tag_oid_basic, octets });
        const explicit = try tlv(a, tag.ctx0, &.{rb});
        return tlv(a, tag.sequence, &.{ &.{ tag.enumerated, 1, 0 }, explicit });
    }

    pub const tag_oid_basic = [_]u8{ tag.oid, oid_ocsp_basic.len } ++ oid_ocsp_basic;

    /// `resp` (one SingleResponse) with its thisUpdate and nextUpdate
    /// replaced, signed again by the test CA.
    pub fn retimed(a: std.mem.Allocator, resp: []const u8, this_update: []const u8, next_update: ?[]const u8) ![]u8 {
        const p = try split(resp);
        return join(a, p, &.{try singleWithTimes(a, p.singles[0], this_update, next_update)}, p.certs);
    }

    /// A response with ResponseData built from `data_head` and `singles`,
    /// signed (ECDSA P-256 with SHA-256) by `signer`, with `certs` (whole).
    pub fn signedBy(a: std.mem.Allocator, data_head: []const u8, singles: []const []const u8, certs: []const u8, signer: *const @import("./credentials.zig").Credentials) ![]u8 {
        const data = try tlv(a, tag.sequence, &.{ data_head, try tlv(a, tag.sequence, singles) });
        var sig_buf: [@import("./credentials.zig").max_signature_len]u8 = undefined;
        const sig = try signer.key.sign(data, @splat(5), &sig_buf);
        const sig_alg = try tlv(a, tag.sequence, &.{&([_]u8{ tag.oid, oid_ecdsa_sha256.len } ++ oid_ecdsa_sha256)});
        const basic = try tlv(a, tag.sequence, &.{ data, sig_alg, try tlv(a, tag.bit_string, &.{ &.{0}, sig }), certs });
        const rb = try tlv(a, tag.sequence, &.{ &tag_oid_basic, try tlv(a, tag.octet_string, &.{basic}) });
        return tlv(a, tag.sequence, &.{ &.{ tag.enumerated, 1, 0 }, try tlv(a, tag.ctx0, &.{rb}) });
    }

    /// As `join`, with `p`'s own signature (good while the ResponseData
    /// is unchanged).
    pub fn joinKeepingSignature(a: std.mem.Allocator, p: Parts, singles: []const []const u8, certs: []const u8) ![]u8 {
        const responses = try tlv(a, tag.sequence, singles);
        const data = try tlv(a, tag.sequence, &.{ p.data_head, responses, p.data_exts });
        const basic = try tlv(a, tag.sequence, &.{ data, p.sig_alg, p.signature, certs });
        const octets = try tlv(a, tag.octet_string, &.{basic});
        const rb = try tlv(a, tag.sequence, &.{ &tag_oid_basic, octets });
        const explicit = try tlv(a, tag.ctx0, &.{rb});
        return tlv(a, tag.sequence, &.{ &.{ tag.enumerated, 1, 0 }, explicit });
    }

    /// A certificate that parses (not signed by anyone), its size set by
    /// a non-critical extension holding `pad` zero bytes.
    pub fn fillerCert(a: std.mem.Allocator, pad: usize) ![]u8 {
        const name = try tlv(a, tag.sequence, &.{try tlv(a, 0x31, &.{try tlv(a, tag.sequence, &.{ &.{ tag.oid, 3, 0x55, 0x04, 0x03 }, try tlv(a, 0x0c, &.{"filler"}) })})});
        const alg = try tlv(a, tag.sequence, &.{&([_]u8{ tag.oid, oid_ecdsa_sha256.len } ++ oid_ecdsa_sha256)});
        const validity = try tlv(a, tag.sequence, &.{ try tlv(a, tag.utc_time, &.{"260101000000Z"}), try tlv(a, tag.utc_time, &.{"491231235959Z"}) });
        const spki = try tlv(a, tag.sequence, &.{
            try tlv(a, tag.sequence, &.{ &([_]u8{ tag.oid, oid_ec_public_key.len } ++ oid_ec_public_key), &([_]u8{ tag.oid, oid_p256.len } ++ oid_p256) }),
            try tlv(a, tag.bit_string, &.{ &.{ 0, 4 }, &@as([64]u8, @splat(1)) }),
        });
        const zeros = try a.alloc(u8, pad);
        @memset(zeros, 0);
        const ext = try tlv(a, tag.sequence, &.{ &.{ tag.oid, 3, 0x2a, 0x03, 0x04 }, try tlv(a, tag.octet_string, &.{zeros}) });
        const exts = try tlv(a, tag.ctx3, &.{try tlv(a, tag.sequence, &.{ext})});
        const tbs = try tlv(a, tag.sequence, &.{ &.{ tag.ctx0, 3, tag.integer, 1, 2 }, &.{ tag.integer, 1, 7 }, alg, name, validity, name, spki, exts });
        return tlv(a, tag.sequence, &.{ tbs, alg, try tlv(a, tag.bit_string, &.{ &.{0}, &@as([8]u8, @splat(2)) }) });
    }

    /// `resp` with its certs field replaced by a filler certificate sized
    /// so the whole response is `total` bytes (certs aren't signed).
    pub fn padded(a: std.mem.Allocator, resp: []const u8, total: usize) ![]u8 {
        const p = try split(resp);
        const singles = p.singles[0..p.single_count];
        const build = struct {
            fn f(al: std.mem.Allocator, parts: Parts, ss: []const []const u8, pad: usize) ![]u8 {
                return join(al, parts, ss, try tlv(al, tag.ctx0, &.{try tlv(al, tag.sequence, &.{try fillerCert(al, pad)})}));
            }
        }.f;
        const smallest = (try build(a, p, singles, 0)).len;
        if (smallest > total) return error.CannotPad;
        var pad = total - smallest;
        for (0..16) |_| {
            const out = try build(a, p, singles, pad);
            if (out.len == total) return out;
            // Lengths of lengths grow with the pad: step back or on.
            if (out.len > total) pad -= @min(pad, out.len - total) else pad += total - out.len;
        }
        return error.CannotPad;
    }
};

/// A SingleResponse (whole) with thisUpdate and nextUpdate replaced.
pub fn singleWithTimes(a: std.mem.Allocator, single: []const u8, this_update: []const u8, next_update: ?[]const u8) ![]u8 {
    var outer: Der = .{ .bytes = single };
    var s: Der = .{ .bytes = try outer.expect(tag.sequence) };
    const cert_id = try s.next();
    const status = try s.next();
    const tu = try craft.tlv(a, tag.generalized_time, &.{this_update});
    const nu = if (next_update) |n| try craft.tlv(a, tag.ctx0, &.{try craft.tlv(a, tag.generalized_time, &.{n})}) else "";
    return craft.tlv(a, tag.sequence, &.{ cert_id.all, status.all, tu, nu });
}

test "verify: crafted responses reproduce the originals" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    for ([_][]const u8{ testdata.leaf_good, testdata.leaf_good_sha256, testdata.both_good, testdata.leaf_revoked }) |r| {
        // The same ResponseData and certificates, signed again.
        const p = try craft.split(r);
        const again = try craft.split(try craft.join(a, p, p.singles[0..p.single_count], p.certs));
        try testing.expectEqualSlices(u8, p.data_head, again.data_head);
        try testing.expectEqual(p.single_count, again.single_count);
        for (p.singles[0..p.single_count], again.singles[0..again.single_count]) |x, y| try testing.expectEqualSlices(u8, x, y);
        try testing.expectEqualSlices(u8, p.certs, again.certs);
        if (r.ptr != testdata.leaf_revoked.ptr and r.ptr != testdata.leaf_good_sha256.ptr) try expectHundredYears(try check(try craft.join(a, p, p.singles[0..p.single_count], p.certs), c.leaf.chain, now));
    }
}

test "verify: several SingleResponses, the one for the leaf decides" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    const good = try craft.split(testdata.leaf_good);
    const revoked = try craft.split(testdata.leaf_revoked);
    const unknown = try craft.split(testdata.leaf_unknown);
    const sni = try craft.split(testdata.sni_good);
    // Another certificate's good one, then the leaf's revoked one.
    try testing.expectError(error.Revoked, check(try craft.join(a, good, &.{ sni.singles[0], revoked.singles[0] }, ""), c.leaf.chain, now));
    try testing.expectError(error.StatusUnknown, check(try craft.join(a, good, &.{ sni.singles[0], unknown.singles[0] }, ""), c.leaf.chain, now));
    // Revoked first, then good: revoked.
    try testing.expectError(error.Revoked, check(try craft.join(a, good, &.{ revoked.singles[0], good.singles[0] }, ""), c.leaf.chain, now));
    // Only another certificate's: not for it.
    try testing.expectError(error.NotForCertificate, check(try craft.join(a, good, &.{ sni.singles[0], sni.singles[0] }, ""), c.leaf.chain, now));
    // Empty responses list.
    try testing.expectError(error.Malformed, check(try craft.join(a, good, &.{}, ""), c.leaf.chain, now));
    // A later SingleResponse that doesn't parse fails the whole response.
    try testing.expectError(error.Malformed, check(try craft.join(a, good, &.{ good.singles[0], &.{ 0x30, 0x00 } }, ""), c.leaf.chain, now));
}

test "verify: times in SingleResponses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const good = try craft.split(testdata.leaf_good);
    const s = good.singles[0];
    const now = testdata.this_update + 3600;
    const R = struct { tu: []const u8, nu: ?[]const u8, want: anyerror!i64 };
    for ([_]R{
        // nextUpdate before thisUpdate.
        .{ .tu = "20261031182506Z", .nu = "20261031182505Z", .want = error.Malformed },
        // Equal: expired at once.
        .{ .tu = "20261031182506Z", .nu = "20261031182506Z", .want = error.Expired },
        // Far future nextUpdate.
        .{ .tu = "20261031182506Z", .nu = "99991231235959Z", .want = 253402300799 },
        // No nextUpdate: a day.
        .{ .tu = "20261031182506Z", .nu = null, .want = testdata.this_update + default_validity_s },
        .{ .tu = "20261030182506Z", .nu = null, .want = error.Expired },
        // Fractional seconds (allowed by DER), offsets and commas not.
        .{ .tu = "20261031182506.5Z", .nu = "20271031182506.123Z", .want = testdata.this_update + 365 * 86400 },
        .{ .tu = "20261031182506+0000", .nu = null, .want = error.Malformed },
        .{ .tu = "20261031182506.50Z", .nu = null, .want = error.Malformed },
        // UTCTime contents in a GeneralizedTime.
        .{ .tu = "261031182506Z", .nu = null, .want = error.Malformed },
    }) |case| {
        const r = try craft.join(a, good, &.{try singleWithTimes(a, s, case.tu, case.nu)}, "");
        if (case.want) |exp| {
            try testing.expectEqual(exp, (try check(r, c.leaf.chain, now)).expires);
        } else |e| try testing.expectError(e, check(r, c.leaf.chain, now));
    }
    // A UTCTime element (tag 0x17) where a GeneralizedTime is required.
    {
        var outer: Der = .{ .bytes = s };
        var sd: Der = .{ .bytes = try outer.expect(tag.sequence) };
        const cert_id = try sd.next();
        const status = try sd.next();
        const utc = try craft.tlv(a, 0x17, &.{"261031182506Z"});
        const single = try craft.tlv(a, tag.sequence, &.{ cert_id.all, status.all, utc });
        try testing.expectError(error.Malformed, check(try craft.join(a, good, &.{single}, ""), c.leaf.chain, now));
    }
}

test "verify: the largest response that passes check fits a CertificateEntry" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    // CertificateEntry: cert_data<1..2^24-1>, extensions<0..2^16-1>; the
    // stapled extension is 8 bytes more than the response.
    for ([_]usize{ 0xffff - 8, 0xffff - 7, max_response_len }) |size| {
        const r = try craft.padded(a, testdata.leaf_good, size);
        try testing.expectEqual(size, r.len);
        if (check(r, c.leaf.chain, now)) |_| {
            try testing.expect(entryLen(r.len) <= 0xffff);
        } else |err| try testing.expectEqual(error.TooLarge, err);
    }
}

test "verify: a response whose thisUpdate is in the future isn't stapled (clients reject it)" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    // A day before the responder says the status was known: OpenSSL's
    // OCSP_check_validity (curl --cert-status, nginx with 300 s of slack)
    // and Firefox refuse such a response.
    const now = testdata.this_update - 86400;
    try testing.expect(std.meta.isError(check(testdata.leaf_good, c.leaf.chain, now)));
}

/// The certificates in a response's certs field, whole.
fn responseCerts(resp: []const u8, out: [][]const u8) ![][]const u8 {
    const p = try craft.split(resp);
    var explicit: Der = .{ .bytes = p.certs };
    var e: Der = .{ .bytes = try explicit.expect(tag.ctx0) };
    var seq: Der = .{ .bytes = try e.expect(tag.sequence) };
    var n: usize = 0;
    while (!seq.atEnd()) : (n += 1) out[n] = (try seq.expectElement(tag.sequence)).all;
    return out[0..n];
}

test "check: every issuer certificate the ResponderID names is tried; in certs the first it names decides (as in OpenSSL)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    // A certificate in the CA's name with another key (the rogue
    // responder's), ahead of the CA in the chain: the CA still signs.
    var rogue_buf: [4][]const u8 = undefined;
    const rogue = (try responseCerts(testdata.leaf_good_rogue, &rogue_buf))[0];
    const chain = [_][]const u8{ c.leaf.chain[0], rogue, c.leaf.chain[1] };
    _ = try check(testdata.leaf_good, &chain, now);
    // The RSA responder's certificate twice in certs: the first decides,
    // the good one first or the spoilt one (OpenSSL refuses that too).
    var certs_buf: [4][]const u8 = undefined;
    const resp_cert = (try responseCerts(testdata.leaf_good_rsa, &certs_buf))[0];
    const spoilt = try a.dupe(u8, resp_cert);
    spoilt[spoilt.len - 10] ^= 1;
    const p = try craft.split(testdata.leaf_good_rsa);
    const certs = try craft.tlv(a, tag.ctx0, &.{try craft.tlv(a, tag.sequence, &.{ spoilt, resp_cert })});
    try testing.expectError(error.UnauthorizedResponder, check(try craft.joinKeepingSignature(a, p, p.singles[0..p.single_count], certs), c.leaf.chain, now));
    const good_first = try craft.tlv(a, tag.ctx0, &.{try craft.tlv(a, tag.sequence, &.{ resp_cert, spoilt })});
    try expectHundredYears(try check(try craft.joinKeepingSignature(a, p, p.singles[0..p.single_count], good_first), c.leaf.chain, now));
    // Only the spoilt one: refused.
    const only_spoilt = try craft.tlv(a, tag.ctx0, &.{try craft.tlv(a, tag.sequence, &.{spoilt})});
    try testing.expectError(error.UnauthorizedResponder, check(try craft.joinKeepingSignature(a, p, p.singles[0..p.single_count], only_spoilt), c.leaf.chain, now));
}

/// The Name "CN=OCSP" crafted responder certificates have.
fn craftName(a: std.mem.Allocator) ![]u8 {
    return craft.tlv(a, tag.sequence, &.{try craft.tlv(a, 0x31, &.{try craft.tlv(a, tag.sequence, &.{ &.{ tag.oid, 3, 0x55, 0x04, 0x03 }, try craft.tlv(a, 0x0c, &.{"OCSP"}) })})});
}

/// A responder certificate the test CA issues, with these extensions
/// (each a whole Extension).
fn craftCert(a: std.mem.Allocator, ca: *const Cert, extensions: []const []const u8) ![]u8 {
    const spki = try craft.tlv(a, tag.sequence, &.{
        try craft.tlv(a, tag.sequence, &.{ &([_]u8{ tag.oid, oid_ec_public_key.len } ++ oid_ec_public_key), &([_]u8{ tag.oid, oid_p256.len } ++ oid_p256) }),
        try craft.tlv(a, tag.bit_string, &.{ &.{ 0, 4 }, &@as([64]u8, @splat(1)) }),
    });
    return craftCertKey(a, ca, spki, extensions);
}

/// As `craftCert`, for the key in `spki` (a whole SubjectPublicKeyInfo).
fn craftCertKey(a: std.mem.Allocator, ca: *const Cert, spki: []const u8, extensions: []const []const u8) ![]u8 {
    const name = try craftName(a);
    const alg = try craft.tlv(a, tag.sequence, &.{&([_]u8{ tag.oid, oid_ecdsa_sha256.len } ++ oid_ecdsa_sha256)});
    const validity = try craft.tlv(a, tag.sequence, &.{ try craft.tlv(a, tag.utc_time, &.{"260101000000Z"}), try craft.tlv(a, tag.utc_time, &.{"491231235959Z"}) });
    const exts = try craft.tlv(a, tag.ctx3, &.{try craft.tlv(a, tag.sequence, extensions)});
    const tbs = try craft.tlv(a, tag.sequence, &.{ &.{ tag.ctx0, 3, tag.integer, 1, 2 }, &.{ tag.integer, 1, 9 }, alg, ca.subject, validity, name, spki, exts });
    const key = try Credentials.fromPem(a, testdata.ca_cert, testdata.ca_key);
    var sig_buf: [@import("./credentials.zig").max_signature_len]u8 = undefined;
    const sig = try key.key.sign(tbs, @splat(3), &sig_buf);
    return craft.tlv(a, tag.sequence, &.{ tbs, alg, try craft.tlv(a, tag.bit_string, &.{ &.{0}, sig }) });
}

fn craftExtension(a: std.mem.Allocator, oid: []const u8, critical: bool, value: []const u8) ![]u8 {
    return craft.tlv(a, tag.sequence, &.{
        try craft.tlv(a, tag.oid, &.{oid}),
        if (critical) &.{ tag.boolean, 1, 0xff } else "",
        try craft.tlv(a, tag.octet_string, &.{value}),
    });
}

test "check: a responder certificate whose keyUsage lacks digitalSignature, or with an unknown critical extension, may not sign" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const ca = try Cert.parse(c.leaf.chain[1]);
    const eku = try craftExtension(a, &oid_ext_ext_key_usage, false, try craft.tlv(a, tag.sequence, &.{&([_]u8{ tag.oid, oid_kp_ocsp_signing.len } ++ oid_kp_ocsp_signing)}));
    const basic = try craftExtension(a, &oid_ext_basic_constraints, true, &.{ tag.sequence, 0 });
    const ku_sign = try craftExtension(a, &oid_ext_key_usage, true, &.{ tag.bit_string, 2, 7, 0x80 });
    const ku_cert_sign = try craftExtension(a, &oid_ext_key_usage, true, &.{ tag.bit_string, 2, 2, 0x04 });
    const unknown = try craftExtension(a, &.{ 0x2a, 0x03, 0x04 }, true, &.{ 0x05, 0 });
    const unknown_non_critical = try craftExtension(a, &.{ 0x2a, 0x03, 0x04 }, false, &.{ 0x05, 0 });
    const nocheck = try craftExtension(a, &oid_pkix_ocsp_nocheck, true, &.{ 0x05, 0 });
    const Case = struct { exts: []const []const u8, unknown_critical: bool };
    for ([_]Case{
        .{ .exts = &.{ eku, basic }, .unknown_critical = false },
        .{ .exts = &.{ eku, basic, ku_sign, unknown_non_critical, nocheck }, .unknown_critical = false },
        // keyUsage without digitalSignature: OpenSSL doesn't mind.
        .{ .exts = &.{ eku, ku_cert_sign }, .unknown_critical = false },
        .{ .exts = &.{ eku, unknown }, .unknown_critical = true },
    }) |case| {
        const cert = try Cert.parse(try craftCert(a, &ca, case.exts));
        try testing.expect(cert.ocsp_signing);
        try testing.expectEqual(case.unknown_critical, cert.unknown_critical);
        if (!case.unknown_critical) {
            try delegatedBy(&cert, &ca);
        } else {
            try testing.expectError(error.UnauthorizedResponder, delegatedBy(&cert, &ca));
        }
    }
    // Malformed extension values make the certificate invalid (keyUsage
    // only when not a BIT STRING at all: OpenSSL takes padding bits and
    // trailing zero octets).
    for ([_][]const u8{
        try craftExtension(a, &oid_ext_key_usage, true, &.{ tag.bit_string, 2, 8, 0x80 }), // 8 unused bits
        try craftExtension(a, &oid_ext_key_usage, true, &.{ tag.bit_string, 1, 3 }), // empty, 3 unused bits
        try craftExtension(a, &oid_ext_key_usage, true, &.{ tag.integer, 1, 3 }), // not a BIT STRING
        try craftExtension(a, &oid_ext_ext_key_usage, false, &.{ tag.sequence, 0 }), // no purposes
        try craftExtension(a, &oid_ext_basic_constraints, true, &.{ tag.sequence, 3, tag.boolean, 1, 0 }), // FALSE written out
        try craftExtension(a, &oid_ext_basic_constraints, true, &.{ tag.sequence, 3, tag.integer, 1, 0xff }), // negative pathLen
        try craftExtension(a, &oid_ext_subject_key_id, false, &.{ tag.integer, 1, 1 }),
        try craftExtension(a, &oid_ext_authority_key_id, false, &.{ tag.sequence, 4, tag.ctx1, 2, tag.sequence, 0 }), // an issuer without a serial
    }) |bad| {
        // (A bad extKeyUsage on its own: two would be invalid anyway.)
        const alone = std.mem.indexOf(u8, bad, &oid_ext_ext_key_usage) != null;
        const exts: []const []const u8 = if (alone) &.{bad} else &.{ eku, bad };
        try testing.expect((try Cert.parse(try craftCert(a, &ca, exts))).invalid);
    }
    // Well-formed ones of those don't.
    const aki = try craftExtension(a, &oid_ext_authority_key_id, false, &.{ tag.sequence, 4, 0x80, 2, 1, 2 });
    const ski = try craftExtension(a, &oid_ext_subject_key_id, false, &.{ tag.octet_string, 2, 1, 2 });
    const bc_path = try craftExtension(a, &oid_ext_basic_constraints, true, &.{ tag.sequence, 6, tag.boolean, 1, 0xff, tag.integer, 1, 0 });
    try testing.expect(!(try Cert.parse(try craftCert(a, &ca, &.{ eku, aki, ski, bc_path }))).invalid);
    for ([_][]const u8{ &.{ tag.bit_string, 2, 7, 0x81 }, &.{ tag.bit_string, 3, 0, 0x80, 0 }, &.{ tag.bit_string, 1, 0 } }) |ku| {
        try testing.expect(!(try Cert.parse(try craftCert(a, &ca, &.{ eku, try craftExtension(a, &oid_ext_key_usage, true, ku) }))).invalid);
    }
    // An empty [3] extensions is malformed; extensions in a v1
    // certificate, or one extension twice among many, invalid.
    const no_exts = try craftCert(a, &ca, &.{});
    try testing.expectError(error.Malformed, Cert.parse(no_exts));
    const v1 = try a.dupe(u8, try craftCert(a, &ca, &.{eku}));
    const at = std.mem.indexOf(u8, v1, &.{ tag.ctx0, 3, tag.integer, 1, 2 }).?;
    v1[at + 4] = 0;
    try testing.expect((try Cert.parse(v1)).invalid);
    var many: [20][]const u8 = undefined;
    for (&many, 0..) |*m, i| m.* = try craftExtension(a, &.{ 0x2a, 0x03, @intCast(i) }, false, &.{ 0x05, 0 });
    var with_dup: [21][]const u8 = undefined;
    @memcpy(with_dup[0..20], &many);
    with_dup[20] = many[0];
    try testing.expect(!(try Cert.parse(try craftCert(a, &ca, &many))).invalid);
    try testing.expect((try Cert.parse(try craftCert(a, &ca, &with_dup))).invalid);
}

test "verifySignature: RSA-PSS with a modulus of 8k + 1 bits, and an RSASSA-PSS key, are unsupported (not handed to std)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A 2041-bit modulus (top byte 1): std's PSS check would assert.
    var modulus: [256]u8 = @splat(0xab);
    modulus[0] = 0x01;
    modulus[255] |= 1;
    const key = try craft.tlv(a, tag.sequence, &.{ try craft.tlv(a, tag.integer, &.{ &.{0}, &modulus }), &.{ tag.integer, 3, 1, 0, 1 } });
    const rsa_alg = [_]u8{ tag.oid, oid_rsa_encryption.len } ++ oid_rsa_encryption ++ [_]u8{ tag.null_, 0 };
    const sha256_alg = try craft.tlv(a, tag.sequence, &.{ &([_]u8{ tag.oid, oid_sha256.len } ++ oid_sha256), &.{ tag.null_, 0 } });
    const pss_params = try craft.tlv(a, tag.sequence, &.{
        try craft.tlv(a, tag.ctx0, &.{sha256_alg}),
        try craft.tlv(a, tag.ctx1, &.{try craft.tlv(a, tag.sequence, &.{ &([_]u8{ tag.oid, oid_mgf1.len } ++ oid_mgf1), sha256_alg })}),
        try craft.tlv(a, tag.ctx2, &.{&.{ tag.integer, 1, 32 }}),
    });
    const pss_alg = try std.mem.concat(a, u8, &.{ &([_]u8{ tag.oid, oid_rsa_pss.len } ++ oid_rsa_pss), pss_params });
    const sig: [256]u8 = @splat(0x33);
    try testing.expectError(error.UnsupportedAlgorithm, verifySignature(pss_alg, &rsa_alg, key, "message", &sig));
    // PKCS#1 v1.5 handles any size: std refuses the signature.
    try testing.expectError(error.BadSignature, verifySignature(&([_]u8{ tag.oid, oid_sha256_rsa.len } ++ oid_sha256_rsa), &rsa_alg, key, "message", &sig));
    // The same key under the RSASSA-PSS key OID.
    const pss_key_alg = [_]u8{ tag.oid, oid_rsa_pss.len } ++ oid_rsa_pss;
    modulus[0] = 0xc1;
    const full = try craft.tlv(a, tag.sequence, &.{ try craft.tlv(a, tag.integer, &.{ &.{0}, &modulus }), &.{ tag.integer, 3, 1, 0, 1 } });
    try testing.expectError(error.UnsupportedAlgorithm, verifySignature(pss_alg, &pss_key_alg, full, "message", &sig));
    // A full-size modulus gets to std, which refuses the signature.
    try testing.expectError(error.BadSignature, verifySignature(pss_alg, &rsa_alg, full, "message", &sig));
}

// -- Adversarial verification, second round -----------------------------

/// Responses from testdata/ocsp/verify/gen.py, by file name: signed by the
/// test CA or by responder certificates it issued, each with one thing
/// changed. `openssl ocsp -verify_other leaf-chain -CAfile ca.pem` (what
/// curl --cert-status runs) says the same as `want` unless noted.
const verify2 = struct {
    const Case = struct { name: []const u8, want: anyerror!void };

    fn load(comptime name: []const u8) []const u8 {
        return @embedFile("testdata/ocsp/verify/" ++ name ++ ".der");
    }

    fn run(comptime cases: []const Case) !void {
        var c = try testChains();
        defer c.leaf.deinit();
        defer c.sni.deinit();
        const now = testdata.this_update + 3600;
        var failed: usize = 0;
        inline for (cases) |case| {
            const got = check(load(case.name), c.leaf.chain, now);
            const ok = if (case.want) |_| !std.meta.isError(got) else |want_err| blk: {
                if (got) |_| break :blk false else |e| break :blk want_err == error.Any or e == want_err;
            };
            if (!ok) {
                failed += 1;
                if (got) |_| {
                    std.debug.print("{s}: accepted, want {any}\n", .{ case.name, case.want });
                } else |e| std.debug.print("{s}: {t}, want {any}\n", .{ case.name, e, case.want });
            }
        }
        try testing.expectEqual(0, failed);
    }
};

test "verify: responses OpenSSL accepts pass check" {
    try verify2.run(&.{
        .{ .name = "deleg-ok", .want = {} },
        .{ .name = "deleg-bykey", .want = {} },
        // id-kp-OCSPSigning among others in a critical extension.
        .{ .name = "eku-critical-several", .want = {} },
        // keyUsage without digitalSignature (neither checks it).
        .{ .name = "ku-no-digital-signature", .want = {} },
        // critical FALSE written out (BER; the certificate is signed as is).
        .{ .name = "critical-false-explicit", .want = {} },
        // Two copies of the responder's certificate, the valid one first.
        .{ .name = "valid-copy-first", .want = {} },
        // Signed by the CA, with a self-signed certificate named like the
        // CA in certs, or the leaf.
        .{ .name = "rogue-ca-named-in-certs", .want = {} },
        .{ .name = "leaf-in-certs", .want = {} },
        // version [0] INTEGER 0 written out (signed as received).
        .{ .name = "version-explicit", .want = {} },
        .{ .name = "rsa", .want = {} },
        .{ .name = "pss", .want = {} },
        .{ .name = "pss-hash-without-null", .want = {} },
        .{ .name = "pss-trailer-1", .want = {} },
        .{ .name = "rsa-e3", .want = {} },
        // A 2041-bit modulus is 256 bytes.
        .{ .name = "rsa-2041-pkcs1", .want = {} },
        // A PKCS#1 signature whose first byte is 0, at full length.
        .{ .name = "rsa-signature-leading-zero", .want = {} },
        .{ .name = "p384-with-sha256", .want = {} },
        .{ .name = "p256-with-sha512", .want = {} },
        // s above n/2 (ECDSA has no low-S rule).
        .{ .name = "ecdsa-high-s", .want = {} },
    });
}

test "verify: responses OpenSSL refuses fail check" {
    try verify2.run(&.{
        // ResponderID byKey with the SHA-1 of the whole SPKI, not of the key bits.
        .{ .name = "bykey-whole-spki", .want = error.UnauthorizedResponder },
        .{ .name = "eku-any-only", .want = error.UnauthorizedResponder },
        // (ResponderNotCurrent: the watcher checks these again later.)
        .{ .name = "responder-not-yet-valid", .want = error.ResponderNotCurrent },
        .{ .name = "responder-expired", .want = error.ResponderNotCurrent },
        // The expired copy first (the first certificate named decides, as in OpenSSL).
        .{ .name = "expired-copy-first", .want = error.ResponderNotCurrent },
        // Signed with the CA's key, but naming another issuer.
        .{ .name = "issuer-field-other-ca", .want = error.UnauthorizedResponder },
        // Issued in the CA's name by another key.
        .{ .name = "other-ca-same-name", .want = error.UnauthorizedResponder },
        // A delegated responder named like the CA (check takes the CA,
        // OpenSSL the certificate: both then fail).
        .{ .name = "named-like-ca", .want = error.BadSignature },
        // ResponderID names the CA; a delegated responder signed.
        .{ .name = "byname-ca-signed-by-delegate", .want = error.BadSignature },
        .{ .name = "rsa-key-ecdsa-oid", .want = error.BadSignature },
        // RSASSA-PSS-params that don't match the signature.
        .{ .name = "pss-said-32-used-20", .want = error.BadSignature },
        .{ .name = "pss-said-32-used-max", .want = error.BadSignature },
        .{ .name = "pss-said-32-used-0", .want = error.BadSignature },
        .{ .name = "pss-said-sha384-used-sha256", .want = error.BadSignature },
        .{ .name = "pss-trailer-2", .want = error.UnsupportedAlgorithm },
        // A PKCS#1 signature a byte longer (a leading 0) or shorter (its leading 0 dropped).
        .{ .name = "rsa-signature-longer", .want = error.BadSignature },
        .{ .name = "rsa-signature-shorter", .want = error.BadSignature },
        // ECDSA: r = 0, s + n, s - n (negative), a byte after the SEQUENCE.
        .{ .name = "ecdsa-r-zero", .want = error.BadSignature },
        .{ .name = "ecdsa-s-plus-n", .want = error.BadSignature },
        .{ .name = "ecdsa-s-minus-n", .want = error.BadSignature },
        .{ .name = "ecdsa-trailing-byte", .want = error.BadSignature },
    });
}

test "verify: algorithms check doesn't support are refused (OpenSSL accepts them)" {
    try verify2.run(&.{
        .{ .name = "pss-mgf-sha1", .want = error.UnsupportedAlgorithm },
        .{ .name = "pss-salt-20", .want = error.UnsupportedAlgorithm },
        .{ .name = "rsa-sha1", .want = error.UnsupportedAlgorithm },
        .{ .name = "rsa-md5", .want = error.UnsupportedAlgorithm },
        .{ .name = "rsa-512", .want = error.UnsupportedAlgorithm },
        .{ .name = "p521", .want = error.UnsupportedAlgorithm },
        // The responder's certificate signed by the CA with ecdsa-with-SHA1.
        .{ .name = "cert-signed-ecdsa-sha1", .want = error.UnsupportedAlgorithm },
        // Ed25519 with parameters (RFC 8410 §3: absent).
        .{ .name = "ed25519-params", .want = error.Malformed },
    });
}

test "verify: a response of 65 KB with 171 certificates, the responder's last, passes check" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const r = try verify2Big(arena.allocator(), verify2.load("rsa"), c.leaf.chain[0], 170);
    try testing.expect(r.len > 65000 and r.len <= max_response_len);
    _ = try check(r, c.leaf.chain, testdata.this_update + 3600);
}

/// `resp` (one responder certificate in certs) with `fillers` copies of
/// the leaf's certificate before the responder's (certs isn't signed).
fn verify2Big(a: std.mem.Allocator, resp: []const u8, leaf_der: []const u8, fillers: usize) ![]u8 {
    const p = try craft.split(resp);
    var certs_outer: Der = .{ .bytes = p.certs };
    var certs_explicit: Der = .{ .bytes = try certs_outer.expect(tag.ctx0) };
    const list = try certs_explicit.expect(tag.sequence);
    var parts: std.ArrayList([]const u8) = .empty;
    for (0..fillers) |_| try parts.append(a, leaf_der);
    try parts.append(a, list);
    const certs = try craft.tlv(a, tag.ctx0, &.{try craft.tlv(a, tag.sequence, parts.items)});
    const responses = try craft.tlv(a, tag.sequence, p.singles[0..p.single_count]);
    const data = try craft.tlv(a, tag.sequence, &.{ p.data_head, responses, p.data_exts });
    const basic = try craft.tlv(a, tag.sequence, &.{ data, p.sig_alg, p.signature, certs });
    const octets = try craft.tlv(a, tag.octet_string, &.{basic});
    const rb = try craft.tlv(a, tag.sequence, &.{ &craft.tag_oid_basic, octets });
    const explicit = try craft.tlv(a, tag.ctx0, &.{rb});
    return craft.tlv(a, tag.sequence, &.{ &.{ tag.enumerated, 1, 0 }, explicit });
}

test "verify: responder certificates OpenSSL refuses (RFC 5280) fail check" {
    try verify2.run(&.{
        // An unknown critical extension (§4.2: MUST reject); OpenSSL:
        // "unhandled critical extension".
        .{ .name = "unknown-critical-extension", .want = error.Any },
        // extendedKeyUsage twice, serverAuth then id-kp-OCSPSigning (§4.2:
        // MUST NOT include more than one instance); OpenSSL: invalid
        // certificate.
        .{ .name = "eku-twice", .want = error.Any },
        // tbsCertificate.signature ecdsa-with-SHA384, signatureAlgorithm
        // ecdsa-with-SHA256 (§4.1.1.2: MUST be the same); OpenSSL:
        // certificate signature failure.
        .{ .name = "cert-tbs-alg-mismatch", .want = error.Any },
    });
}

test "verify: ECDSA signatures that aren't DER fail check (OpenSSL refuses them)" {
    try verify2.run(&.{
        // r < 2^247 written as 32 bytes, a needless leading 0 (std's
        // Signature.fromDer checks the top bit only at 33 bytes).
        .{ .name = "ecdsa-r-not-minimal", .want = error.BadSignature },
        // 2^247 <= r < 2^248 written as 31 bytes without the leading 0
        // (negative in DER).
        .{ .name = "ecdsa-r-negative", .want = error.BadSignature },
    });
}

test "verify: what check doesn't use must still parse (OpenSSL can't parse the response at all)" {
    // curl --cert-status, nginx and s_client -status fail with "Error
    // parsing response": a staple a client can't parse is worse than none.
    try verify2.run(&.{
        // certs [0] holding an INTEGER (the CA signed; certs isn't read).
        .{ .name = "garbage-certs", .want = error.Malformed },
        // An INTEGER after the delegated responder's certificate.
        .{ .name = "garbage-after-responder", .want = error.Malformed },
        // singleExtensions [1] and responseExtensions [1] holding a NULL.
        .{ .name = "garbage-single-extensions", .want = error.Malformed },
        .{ .name = "garbage-response-extensions", .want = error.Malformed },
    });
}

test "verify: RSA-PSS with a 2041-bit responder key doesn't panic (refused as unsupported)" {
    // Run on its own (-Dtest-filter): it panics in Debug and ReleaseSafe
    // (ReleaseFast: undefined behaviour) and takes the test run with it.
    // A modulus of 8k+1 bits (2041, 3065, 4089) is 256, 384 or 512 bytes,
    // but its PSS encoded message is a byte shorter: std's
    // PSSSignature.verify asserts `emLen == em.len` (rsa_verify.zig's
    // verifyWithStd skips these sizes for that reason). The same
    // happens with an issuer key of those sizes and any response naming
    // RSA-PSS, whatever its bytes; in the server it is the watcher thread
    // (or init) that dies, with the process. OpenSSL verifies the response.
    // OpenSSL verifies it; check refuses it rather than reach std.
    try verify2.run(&.{.{ .name = "rsa-2041-pss", .want = error.UnsupportedAlgorithm }});
}

test "check: a ResponderID naming the issuer means the issuer the CertID names (not another of its name in the chain)" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    // leaf-good-rogue.der: named like the CA, signed by the rogue key,
    // the CertID naming the CA's key. With the rogue certificate in the
    // chain as well, it still isn't the issuer the CertID names.
    var rogue_buf: [4][]const u8 = undefined;
    const rogue = (try responseCerts(testdata.leaf_good_rogue, &rogue_buf))[0];
    const chain = [_][]const u8{ c.leaf.chain[0], rogue, c.leaf.chain[1] };
    try testing.expectError(error.BadSignature, check(testdata.leaf_good_rogue, &chain, now));
    const chain2 = [_][]const u8{ c.leaf.chain[0], c.leaf.chain[1], rogue };
    try testing.expectError(error.BadSignature, check(testdata.leaf_good_rogue, &chain2, now));
}

test "check: a delegated responder may answer only for its issuer's certificates; the issuer may answer for several" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const now = testdata.this_update + 3600;
    const ca = try Cert.parse(c.leaf.chain[1]);
    // A responder certificate for the leaf's key (whose private key the
    // tests have), issued by the CA with id-kp-OCSPSigning.
    const spki = (try Cert.parse(c.leaf.chain[0])).spki;
    const eku = try craftExtension(a, &oid_ext_ext_key_usage, false, try craft.tlv(a, tag.sequence, &.{&([_]u8{ tag.oid, oid_kp_ocsp_signing.len } ++ oid_kp_ocsp_signing)}));
    const responder = try craftCertKey(a, &ca, spki, &.{eku});
    const certs = try craft.tlv(a, tag.ctx0, &.{try craft.tlv(a, tag.sequence, &.{responder})});
    const head = try std.mem.concat(a, u8, &.{ try craft.tlv(a, tag.ctx1, &.{try craftName(a)}), try craft.tlv(a, tag.generalized_time, &.{"20261031182506Z"}) });
    const good = try craft.split(testdata.leaf_good);
    // A second SingleResponse whose CertID names another issuer key.
    const other = try a.dupe(u8, good.singles[0]);
    const kh = std.mem.indexOfPos(u8, other, std.mem.indexOf(u8, other, &.{ 0x04, 0x14 }).? + 22, &.{ 0x04, 0x14 }).? + 2;
    other[kh] ^= 1;
    // The leaf's key signs.
    const signer = try Credentials.fromPem(a, testdata.leaf_chain, testdata.leaf_key);
    // (Stapled until the responder certificate's notAfter, in 2049.)
    _ = try check(try craft.signedBy(a, head, &.{good.singles[0]}, certs, &signer), c.leaf.chain, now);
    try testing.expectError(error.UnauthorizedResponder, check(try craft.signedBy(a, head, &.{ good.singles[0], other }, certs, &signer), c.leaf.chain, now));
    // The CA itself may.
    try expectHundredYears(try check(try craft.join(a, good, &.{ good.singles[0], other }, ""), c.leaf.chain, now));
}

test "check: a leaf that doesn't parse is reported as such, not as a bad response" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const chain = [_][]const u8{ "not a certificate", c.leaf.chain[1] };
    try testing.expectError(error.InvalidCertificate, check(testdata.leaf_good, &chain, testdata.this_update + 3600));
}

test "verify and evaluate: what time decides is apart from the rest" {
    var c = try testChains();
    defer c.leaf.deinit();
    defer c.sni.deinit();
    const td = testdata;
    const v = try verify(td.leaf_good_shortlived, c.leaf.chain);
    try testing.expectEqual(Status.good, v.status);
    try testing.expectError(error.ResponderNotCurrent, evaluate(v, td.this_update - 3600));
    _ = try evaluate(v, td.this_update + 3600);
    try testing.expectError(error.ResponderNotCurrent, evaluate(v, td.this_update + 2 * 86400));
    const r = try verify(td.leaf_revoked, c.leaf.chain);
    try testing.expectEqual(Status.revoked, r.status);
    try testing.expectError(error.Revoked, evaluate(r, td.this_update + 3600));
    try testing.expectError(error.Expired, evaluate(r, td.next_update));
}

// -- Adversarial verification, third round --------------------------------

/// Real responses (testdata/ocsp/real/, fetched 2026-10-31 with
/// `openssl ocsp -issuer -cert -url -respout` from each site's CA, its
/// chain as the site served it): name.chain.der (DER certificates, leaf
/// first) and name.ocsp.der. `openssl ocsp -CAfile issuer -partial_chain`
/// says "Response verify OK ... good" for every one at `time`.
const verify3 = struct {
    const Real = struct { name: []const u8, time: i64 };
    const real = [_]Real{
        .{ .name = "github-com", .time = 1793482783 },
        .{ .name = "sectigo-com", .time = 1793482783 },
        .{ .name = "actalis-it", .time = 1793482783 },
        .{ .name = "adobe-com", .time = 1793482783 },
        .{ .name = "amazon-com", .time = 1793482783 },
        .{ .name = "camerfirma-com", .time = 1793482783 },
        .{ .name = "chase-com", .time = 1793482784 },
        .{ .name = "digicert-com", .time = 1793482783 },
        .{ .name = "ebay-com", .time = 1793482783 },
        .{ .name = "entrust-com", .time = 1793482783 },
        .{ .name = "godaddy-com", .time = 1793482783 },
        .{ .name = "ibm-com", .time = 1793482783 },
        .{ .name = "izenpe-com", .time = 1793482783 },
        .{ .name = "netlock-hu", .time = 1793482783 },
        .{ .name = "oracle-com", .time = 1793482783 },
        .{ .name = "paypal-com", .time = 1793482783 },
        .{ .name = "quovadisglobal-com", .time = 1793482783 },
        .{ .name = "sk-ee", .time = 1793482783 },
        .{ .name = "ssl-com", .time = 1793482784 },
        .{ .name = "telekom-de", .time = 1793482783 },
        .{ .name = "twca-com-tw", .time = 1793482785 },
        .{ .name = "wellsfargo-com", .time = 1793482783 },
        .{ .name = "yahoo-com", .time = 1793482783 },
    };

    const Case = struct { name: []const u8, want: anyerror!void };

    /// Responses from testdata/ocsp/verify3/gen.py, checked a minute
    /// after thisUpdate (when gen.py asks OpenSSL).
    fn run(comptime cases: []const Case) !void {
        var c = try testChains();
        defer c.leaf.deinit();
        defer c.sni.deinit();
        var failed: usize = 0;
        inline for (cases) |case| {
            const got = check(@embedFile("testdata/ocsp/verify3/" ++ case.name ++ ".der"), c.leaf.chain, testdata.this_update + 60);
            const ok = if (case.want) |_| !std.meta.isError(got) else |want_err| blk: {
                if (got) |_| break :blk false else |e| break :blk want_err == error.Any or e == want_err;
            };
            if (!ok) {
                failed += 1;
                if (got) |_| {
                    std.debug.print("{s}: accepted, want {any}\n", .{ case.name, case.want });
                } else |e| std.debug.print("{s}: {t}, want {any}\n", .{ case.name, e, case.want });
            }
        }
        try testing.expectEqual(0, failed);
    }

    fn chainOf(der: []const u8, out: [][]const u8) ![]const []const u8 {
        var d: Der = .{ .bytes = der };
        var n: usize = 0;
        while (!d.atEnd()) : (n += 1) out[n] = (try d.expectElement(tag.sequence)).all;
        return out[0..n];
    }
};

test "verify: real responses from 23 CAs' responders pass check (OpenSSL verifies each)" {
    var failed: usize = 0;
    inline for (verify3.real) |r| {
        var buf: [8][]const u8 = undefined;
        const chain = try verify3.chainOf(@embedFile("testdata/ocsp/real/" ++ r.name ++ ".chain.der"), &buf);
        const resp = @embedFile("testdata/ocsp/real/" ++ r.name ++ ".ocsp.der");
        if (check(resp, chain, r.time)) |c| {
            if (c.expires <= r.time) failed += 1;
        } else |err| {
            failed += 1;
            std.debug.print("{s}: {t}\n", .{ r.name, err });
        }
    }
    try testing.expectEqual(0, failed);
}

test "verify: responder certificates as CAs issue them pass check (OpenSSL accepts each)" {
    try verify3.run(&.{
        // basicConstraints (critical, empty), keyUsage digitalSignature
        // (critical), extKeyUsage, SKI, AKI, id-pkix-ocsp-nocheck (RFC 6960
        // §4.2.2.2.1, non-critical NULL), certificatePolicies with a CPS
        // qualifier, CRL distribution points, AIA; by name and by key.
        .{ .name = "deleg-like-a-ca-issues", .want = {} },
        .{ .name = "deleg-like-a-ca-issues-bykey", .want = {} },
        // keyUsage digitalSignature with unused bits 0 (trailing zero bits
        // kept), in two bytes, and with a padding bit set (not DER).
        .{ .name = "deleg-ku-unused-0", .want = {} },
        .{ .name = "deleg-ku-two-bytes", .want = {} },
        .{ .name = "deleg-ku-padding-set", .want = {} },
        // Good, then revoked, for the leaf in one response: the first decides
        // (OpenSSL's OCSP_resp_find_status too).
        .{ .name = "good-then-revoked", .want = {} },
    });
}

test "verify: a revocation from a responder that may not sign, or for another serial, isn't Revoked (it mustn't stop stapling)" {
    try verify3.run(&.{
        .{ .name = "revoked-by-noeku", .want = error.UnauthorizedResponder },
        .{ .name = "revoked-by-other-ca-same-name", .want = error.UnauthorizedResponder },
        .{ .name = "revoked-by-self-signed", .want = error.UnauthorizedResponder },
        .{ .name = "revoked-by-expired-responder", .want = error.ResponderNotCurrent },
        .{ .name = "unknown-by-noeku", .want = error.UnauthorizedResponder },
        .{ .name = "revoked-other-serial", .want = error.NotForCertificate },
        // keyUsage keyEncipherment only: OpenSSL verifies the signature and
        // reports "revoked", and so does check (it must act on what
        // clients would believe).
        .{ .name = "revoked-by-ku-no-ds", .want = error.Revoked },
    });
}

test "verify: names equal by RFC 5280 but encoded differently are refused (OpenSSL accepts them); critical extensions OpenSSL knows and BER TRUE pass" {
    // Names are compared as bytes, an open item: fail safe for stapling
    // (nothing stapled), though a revocation signed so wouldn't stop it.
    try verify3.run(&.{
        // ResponderID byName: the CA's name as PrintableString (the CA's
        // certificate has UTF8String), or in lower case (RFC 5280 §7.1
        // compares case-insensitively; OpenSSL's X509_NAME_cmp too).
        .{ .name = "responderid-printable", .want = error.UnauthorizedResponder },
        .{ .name = "responderid-case", .want = error.UnauthorizedResponder },
        // A delegated responder named by PrintableString; one whose issuer
        // field has the CA's name as PrintableString.
        .{ .name = "deleg-responderid-printable", .want = error.UnauthorizedResponder },
        .{ .name = "deleg-issuer-printable", .want = error.UnauthorizedResponder },
        // Critical id-pkix-ocsp-nocheck, certificatePolicies,
        // subjectAltName, nameConstraints (OpenSSL handles each).
        .{ .name = "deleg-nocheck-critical", .want = {} },
        .{ .name = "deleg-policies-critical", .want = {} },
        .{ .name = "deleg-san-critical", .want = {} },
        .{ .name = "deleg-name-constraints-critical", .want = {} },
        // critical BOOLEAN 0x01 (BER TRUE).
        .{ .name = "deleg-critical-ber-true", .want = {} },
        // extendedKeyUsage twice with the first among the first 16.
        .{ .name = "deleg-eku-twice-first-16", .want = error.UnauthorizedResponder },
        .{ .name = "deleg-ku-twice-after-16", .want = error.UnauthorizedResponder },
    });
}

test "verify: a responder certificate with an extension twice past its sixteenth fails check (OpenSSL refuses it)" {
    // Cert.parse remembers the first 16 extension OIDs only: 16 harmless
    // extensions, then extendedKeyUsage (serverAuth) and extendedKeyUsage
    // (id-kp-OCSPSigning) get through. RFC 5280 §4.2: "MUST NOT include
    // more than one instance of a particular extension"; OpenSSL: invalid
    // certificate (with the first instance among the first 16, check
    // refuses it too: deleg-eku-twice-first-16).
    try verify3.run(&.{.{ .name = "deleg-eku-twice-after-16", .want = error.Any }});
}
