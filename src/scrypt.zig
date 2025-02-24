const std = @import("std");
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const scrypt = std.crypto.pwhash.scrypt;
const Allocator = std.mem.Allocator;

const bech32 = @import("bech32.zig");
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

const key_label = "age-encryption.org/v1/scrypt";
const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
const rounds = 8;
const parallization = 1;

const Self = @This();

pub fn toString(allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
    var buf = [_]u8{0} ** 128;
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

pub fn unwrap(allocator: Allocator, password: []const u8, args: [][]u8, body: []u8) !Key {
    var key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key);

    // derived from the bech32 encoded
    // identity supplied by the user
    var x25519_secret_key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &x25519_secret_key);

    // the encrypted file key
    var file_key_enc: [32]u8 = undefined;

    // the key label and base64 decoded salt
    // derived from the recipients arg
    var salt: [key_label.len+16]u8 = undefined;
    @memcpy(salt[0..key_label.len], key_label);

    // derived from the last 16 bytes
    // of the recipients body, the Poly
    var tag: [16]u8 = undefined;

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    const decoder = std.base64.Base64Decoder.init(base64_alphabet, null);
    // because we swap the first arg out our salt
    // ends up being the second arg
    try decoder.decode(salt[key_label.len..], args[1]);
    try decoder.decode(&file_key_enc, body);

    const work_factor: u6 = @intCast(try std.fmt.parseInt(u6, args[0], 10));
    try scrypt.kdf(
        allocator,
        &key,
        password,
        &salt,
        .{.r=rounds, .p=parallization, .ln=work_factor}
    );

    const tag_start = file_key_enc.len - ChaCha20Poly1305.tag_length;
    @memcpy(&tag, file_key_enc[tag_start..]);

    const payload = file_key_enc[0..tag_start];
    const file_key: Key = .{
        .k = try allocator.alloc(u8, payload.len),
    };

    try ChaCha20Poly1305.decrypt(file_key.k, payload, tag, &ad, nonce, key);

    return file_key;
}

/// Encrypts the file key in the recipients body
/// and populates the recipients type, args, and body
/// caller is responsible for deinit on the reciepient
pub fn wrap(allocator: Allocator, file_key: Key, password: []const u8) !Recipient {
    // scrypt derived key from the password
    var key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key);

    // the encrypted file key and tag to be base64
    // encoded and written to the reciepient's body
    var file_key_enc: [32]u8 = undefined;

    var salt: [key_label.len+16]u8 = undefined;
    @memcpy(salt[0..key_label.len], key_label);

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

    _ = std.os.linux.getrandom(
        salt[key_label.len..],
        salt.len,
        0x0002 // GRND_RANDOM
    );

    const work_factor: u6 = 15;
    try scrypt.kdf(
        allocator,
        &key,
        password,
        &salt,
        .{.r=rounds, .p=parallization, .ln=work_factor}
    );

    ChaCha20Poly1305.encrypt(file_key_enc[0..16], &tag, file_key.key(), &ad, nonce, key);

    @memcpy(file_key_enc[16..], &tag);

    const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);
    _ = encoder.encode(&body, &file_key_enc);
    const salt_b64 = encoder.encode(&salt_b64_buf, salt[key_label.len..]);

    var args = try allocator.alloc([]u8, 2);
    args[0] = try allocator.dupe(u8, salt_b64);
    args[1] = try std.fmt.allocPrint(allocator, "{d}", .{work_factor});

    return .{
        .type = .scrypt,
        .args = args,
        .body = try allocator.dupe(u8, &body),
    };
}
