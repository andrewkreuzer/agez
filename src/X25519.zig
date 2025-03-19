const std = @import("std");
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const Allocator = std.mem.Allocator;

const bech32 = @import("bech32.zig");
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

pub const stanza_arg = "X25519";
pub const bech32_hrp_private = "AGE-SECRET-KEY-";
const bech32_hrp_public = "age";
pub const bech32_max_len = 90;
const key_label = "age-encryption.org/v1/X25519";

pub fn toStanza(allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
    var buf = [_]u8{0} ** 97;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try std.fmt.format(
        writer,
        \\-> X25519 {s}
        \\{s}
        ,.{args[0], body}
    );

    return try allocator.dupe(u8, &buf);
}

pub fn fromPublicKey(allocator: Allocator, s: []const u8, file_key: Key) !Recipient {
    var recipient_buf: [90]u8 = undefined;
    const decoded = try bech32.decode(&recipient_buf, bech32_hrp_public, s);

    const public_key: Key = .{
        .slice = .{ .k = try allocator.alloc(u8, 32) }
    };
    _ = try bech32.convertBits(public_key.slice.k, decoded.data, 5, 8, false);

    var recipient = Recipient{ .type = .X25519 };
    try recipient.wrap(allocator, file_key, public_key);
    return recipient;
}

pub fn fromPrivateKey(allocator: Allocator, s: []const u8, file_key: Key) !Recipient {
    var recipient_buf: [90]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &recipient_buf);
    var secret_key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &secret_key);

    const decoded = try bech32.decode(&recipient_buf, bech32_hrp_private, s);
    _ = try bech32.convertBits(&secret_key, decoded.data, 5, 8, false);
    const pk = try X25519.recoverPublicKey(secret_key);
    const public_key: Key = try Key.init(allocator, pk);

    var r = Recipient{ .type = .X25519 };
    try r.wrap(allocator, file_key, public_key);
    return r;
}

/// Decrypts the recipients body and returns the file key
pub fn unwrap(allocator: Allocator, identity: []const u8, args: [][]u8, body: []u8) !Key {
    // derived from the shared secret and salt
    // decrypts the file key from the recipients body
    var key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key);

    // derived from the bech32 encoded
    // identity supplied by the user
    var x25519_secret_key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &x25519_secret_key);

    // the encrypted file key
    var file_key_enc: [32]u8 = undefined;

    // the epehemeral share base64 decoded
    var ephemeral_share: [32]u8 = undefined;

    // derived from the recipients ephemeral share
    // and the recipients public key
    var salt: [64]u8 = undefined;

    // derived from the last 16 bytes
    // of the recipients body, the Poly
    var tag: [16]u8 = undefined;

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    // space to decode the recipients bech32 identity
    var identity_buf: [bech32_max_len]u8 = undefined;

    if (args.len != 1) {
        return error.InvalidRecipientArgs;
    }

    const Decoder = std.base64.standard_no_pad.Decoder;
    Decoder.decode(&ephemeral_share, args[0]) catch {
        return error.InvalidX25519Argument;
    };
    Decoder.decode(&file_key_enc, body) catch {
        return error.InvalidX25519Body;
    };

    const Bech32 = bech32.decode(&identity_buf, bech32_hrp_private, identity) catch {
        return error.InvalidX25519Identity;
    };
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);

    const public_key = try X25519.recoverPublicKey(x25519_secret_key);

    var shared_secret = try X25519.scalarmult(x25519_secret_key, ephemeral_share);
    defer std.crypto.utils.secureZero(u8, &shared_secret);

    @memcpy(salt[0..32], &ephemeral_share);
    @memcpy(salt[32..], &public_key);

    const k = hkdf.extract(&salt, &shared_secret);
    hkdf.expand(&key, key_label, k);

    const tag_start = file_key_enc.len - ChaCha20Poly1305.tag_length;
    @memcpy(&tag, file_key_enc[tag_start..]);

    const payload = file_key_enc[0..tag_start];
    const file_key: Key = .{
        .slice = .{ .k = try allocator.alloc(u8, payload.len) }
    };

    try ChaCha20Poly1305.decrypt(file_key.slice.k, payload, tag, &ad, nonce, key);

    return file_key;
}

/// Encrypts the file key in the recipients body
/// and populates the recipients type, args, and body
/// caller is responsible for deinit on the reciepient
pub fn wrap(allocator: Allocator, file_key: Key, public_key: Key) !Recipient {
    // derived from the shared secret and salt
    // encrypts the file key in the recipients body
    var key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key);

    // a randomly generated ephemeral secret
    // currently only supported on linux
    // as it's pulled from /dev/random
    var ephemeral_secret: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &ephemeral_secret);

    // the encrypted file key and tag to be base64
    // encoded and written to the reciepient's body
    var file_key_enc: [32]u8 = undefined;

    // derived from the ephemeral share
    // and the recipients public key
    var salt: [64]u8 = undefined;

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    // tag returned from ChaCha20Poly1305
    var tag: [16]u8 = undefined;

    // base64 encoded ephemeral share
    // to be written to the reciepient
    var ephemeral_share_b64: [43]u8 = undefined;

    // the encrypted file key base64 encoded
    var body: [43]u8 = undefined;

    _ = std.os.linux.getrandom(
        &ephemeral_secret,
        ephemeral_secret.len,
        0x0002 // GRND_RANDOM
    );

    const pk = public_key.key().bytes;

    const ephemeral_share = try X25519.recoverPublicKey(ephemeral_secret);
    var shared_secret = try X25519.scalarmult(ephemeral_secret, pk[0..32].*);
    defer std.crypto.utils.secureZero(u8, &shared_secret);

    @memcpy(salt[0..32], &ephemeral_share);
    @memcpy(salt[32..], pk);

    const k = hkdf.extract(&salt, &shared_secret);
    hkdf.expand(&key, key_label, k);

    ChaCha20Poly1305.encrypt(file_key_enc[0..16], &tag, file_key.key().bytes, &ad, nonce, key);

    @memcpy(file_key_enc[16..], &tag);

    const Encoder = std.base64.standard_no_pad.Encoder;
    _ = Encoder.encode(&body, &file_key_enc);
    _ = Encoder.encode(&ephemeral_share_b64, &ephemeral_share);

    var args = try allocator.alloc([]u8, 1);
    args[0] = try allocator.dupe(u8, &ephemeral_share_b64);

    return .{
        .type = .X25519,
        .args = args,
        .body = try allocator.dupe(u8, &body),
    };
}

const X25519Errors = error{
    InvalidX25519Identity,
    InvalidX25519Argument,
    InvalidX25519Body,
};
