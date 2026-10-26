//! Protocol errors, each named after the alert it is reported with.
const std = @import("std");
const Description = std.crypto.tls.Alert.Description;

pub const Error = error{
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    IllegalParameter,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InternalError,
    MissingExtension,
    UnsupportedExtension,
    NoApplicationProtocol,
};

pub fn alertFor(err: Error) Description {
    return switch (err) {
        error.UnexpectedMessage => .unexpected_message,
        error.BadRecordMac => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.HandshakeFailure => .handshake_failure,
        error.IllegalParameter => .illegal_parameter,
        error.DecodeError => .decode_error,
        error.DecryptError => .decrypt_error,
        error.ProtocolVersion => .protocol_version,
        error.InternalError => .internal_error,
        error.MissingExtension => .missing_extension,
        error.UnsupportedExtension => .unsupported_extension,
        error.NoApplicationProtocol => .no_application_protocol,
    };
}
