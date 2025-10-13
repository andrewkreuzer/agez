const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const scrypt = std.crypto.pwhash.scrypt;
const Allocator = std.mem.Allocator;

const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

pub const STANZA_ARG = "scrypt";
const KEY_LABEL = "age-encryption.org/v1/scrypt";

const rounds = 8;
const parallization = 1;

pub fn toStanza(allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try std.fmt.format(
        writer,
        \\-> scrypt {s} {s}
        \\{s}
        ,.{args[0], args[1], body}
    );

    return try allocator.dupe(u8, fbs.getWritten());
}

pub fn fromPassphrase(allocator: Allocator, passphrase: []const u8, file_key: Key) !Recipient {
    var r = Recipient{ .type = .scrypt };
    const key: Key = try Key.init(allocator, passphrase);
    try r.wrap(allocator, file_key, key, .{});
    return r;
}

/// Decrypts the recipients body and returns the file key
pub fn unwrap(allocator: Allocator, passphrase: []const u8, args: [][]u8, body: []u8) !Key {
    // stanza body encryption key
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);

    // the encrypted file key
    var file_key_enc: [32]u8 = undefined;

    // the key label and base64 decoded salt
    // derived from the recipients arg
    var salt: [KEY_LABEL.len+16]u8 = undefined;
    @memcpy(salt[0..KEY_LABEL.len], KEY_LABEL);

    // derived from the last 16 bytes
    // of the recipients body, the Poly
    var tag: [16]u8 = undefined;

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    if (args.len != 2) return error.InvalidRecipientArgs;
    if (args[1][0] == '0') return error.InvalidScryptWorkFactor;
    if (args[1][0] == '+') return error.InvalidScryptWorkFactor;
    const work_factor = std.fmt.parseInt(u6, args[1], 0) catch {
        return error.InvalidScryptWorkFactor;
    };
    if (work_factor > 20) {
        return error.InvalidScryptWorkFactor;
    }

    const Decoder = std.base64.standard_no_pad.Decoder;
    const body_len = try Decoder.calcSizeForSlice(body);
    if (body_len != 32) {
        return error.InvalidScryptKeyLength;
    }
    const salt_len = try Decoder.calcSizeForSlice(args[0]);
    if (salt_len != 16) {
        return error.InvalidScryptSaltLength;
    }
    Decoder.decode(salt[KEY_LABEL.len..], args[0]) catch {
        return error.InvalidScryptSalt;
    };
    Decoder.decode(&file_key_enc, body) catch {
        return error.InvalidScryptBody;
    };

    try scrypt.kdf(
        allocator,
        &key,
        passphrase,
        &salt,
        .{.r=rounds, .p=parallization, .ln=work_factor}
    );

    const tag_start = file_key_enc.len - ChaCha20Poly1305.tag_length;
    @memcpy(&tag, file_key_enc[tag_start..]);

    const payload = file_key_enc[0..tag_start];
    const file_key: Key = .{
        .slice = .{ .k = try allocator.alloc(u8, payload.len) }
    };
    errdefer file_key.deinit(allocator);

    try ChaCha20Poly1305.decrypt(file_key.slice.k, payload, tag, &ad, nonce, key);

    return file_key;
}

/// Encrypts the file key in the recipients body
/// and returns a new recipient with type, args, and body
/// caller is responsible for deinit on the reciepient
pub fn wrap(allocator: Allocator, file_key: Key, passphrase: Key, work_factor: u6) !Recipient {
    // scrypt derived key from the passphrase
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);

    // the encrypted file key and tag to be base64
    // encoded and written to the reciepient's body
    var file_key_enc: [32]u8 = undefined;

    var salt: [KEY_LABEL.len+16]u8 = undefined;
    @memcpy(salt[0..KEY_LABEL.len], KEY_LABEL);

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    // tag returned from ChaCha20Poly1305
    var tag: [16]u8 = undefined;

    // base64 encoded ephemeral share
    // to be written to the reciepient
    var salt_b64_buf: [60]u8 = undefined;

    // the encrypted file key base64 encoded
    var body: [43]u8 = undefined;

    std.crypto.random.bytes(salt[KEY_LABEL.len..]);

    try scrypt.kdf(
        allocator,
        &key,
        passphrase.key().bytes,
        &salt,
        .{.r=rounds, .p=parallization, .ln=work_factor}
    );

    ChaCha20Poly1305.encrypt(file_key_enc[0..16], &tag, file_key.key().bytes, &ad, nonce, key);

    @memcpy(file_key_enc[16..], &tag);

    const Encoder = std.base64.standard_no_pad.Encoder;
    _ = Encoder.encode(&body, &file_key_enc);
    const salt_b64 = Encoder.encode(&salt_b64_buf, salt[KEY_LABEL.len..]);

    var args = try allocator.alloc([]u8, 2);
    args[0] = try allocator.dupe(u8, salt_b64);
    args[1] = try std.fmt.allocPrint(allocator, "{d}", .{work_factor});

    return .{
        .type = .scrypt,
        .args = args,
        .body = try allocator.dupe(u8, &body),
    };
}

const ScryptErrors = error{
    InvalidScryptWorkFactor,
    InvalidScryptSalt,
    InvalidScryptBody,
    InvalidScryptKeyLength,
    InvalidScryptSaltLength,
};
