const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;

const bech32 = @import("bech32.zig");

const State = enum {
    uninitialized,
    initialized,
    unwrapped,
    wrapped,
};

pub const Recipient = struct {
    const Self = @This();

    const bech32_hrp = "AGE-SECRET-KEY-";
    const bech32_max_len = 90;
    const key_label = "age-encryption.org/v1/X25519";
    pub const x25519_recipient_type = "X25519";

    const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;

    type: ?[]const u8 = null,
    args: ?[][]u8 = null,
    body: ?[]u8 = null,
    state: State = .uninitialized,

    public_key: ?[32]u8 = null,
    ephemeral_share: [32]u8 = [_]u8{0} ** 32,
    file_key_enc: [32]u8 = undefined,

    pub fn init(self: *Self) !void {
        const decoder = std.base64.Base64Decoder.init(base64_alphabet, null);
        try decoder.decode(&self.ephemeral_share, self.args.?[0]);
        try decoder.decode(&self.file_key_enc, self.body.?);
        self.state = .initialized;
    }

    /// Decrypts the file key from the recipients body
    /// it is the callers responsibility to ensure safety
    /// and deallocation of the decrypted file key
    pub fn unwrap(self: *Self, allocator: Allocator, identity: []const u8) ![]const u8 {
        self.state = .unwrapped;

        // derived from the shared secret and salt
        // decrypts the file key from the recipients body
        var key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &key);

        // derived from the bech32 encoded
        // identity supplied by the user
        var x25519_secret_key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &x25519_secret_key);

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

        const Bech32 = try bech32.decode(&identity_buf, bech32_hrp, identity);
        _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);

        self.public_key = try X25519.recoverPublicKey(x25519_secret_key);

        var shared_secret = try X25519.scalarmult(x25519_secret_key, self.ephemeral_share);
        defer std.crypto.utils.secureZero(u8, &shared_secret);

        @memcpy(salt[0..32], &self.ephemeral_share);
        @memcpy(salt[32..], &self.public_key.?);

        const k = hkdf.extract(&salt, &shared_secret);
        hkdf.expand(&key, key_label, k);

        const tag_start = self.file_key_enc.len - ChaCha20Poly1305.tag_length;
        @memcpy(&tag, self.file_key_enc[tag_start..]);

        const payload = self.file_key_enc[0..tag_start];
        const file_key = try allocator.alloc(u8, payload.len);

        try ChaCha20Poly1305.decrypt(file_key, payload, tag, &ad, nonce, key);

        return file_key;
    }

    /// Encrypts the file key in the recipients body
    /// and populates the recipients type, args, and body
    /// caller is responsible for deinit on the reciepient
    pub fn wrap(self: *Self, allocator: Allocator, file_key: []const u8, identity: []const u8) !void {

        // derived from the shared secret and salt
        // encrypts the file key in the recipients body
        var key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &key);

        // derived from the bech32 encoded
        // identity supplied by the user
        var x25519_secret_key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &x25519_secret_key);

        // a randomly generated ephemeral secret
        // currently only supported on linux
        // as it's pulled from /dev/random
        var ephemeral_secret: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &ephemeral_secret);

        // the encrypted file key to be base64 encoded
        // and written to the reciepient's body
        var ciphertext: [16]u8 = undefined;

        // derived from the ephemeral share
        // and the recipients public key
        var salt: [64]u8 = undefined;

        // a blank nonce
        const nonce = [_]u8{0x00} ** 12;

        // an empty associated data
        const ad = [_]u8{};

        // tag returned from ChaCha20Poly1305
        var tag: [16]u8 = undefined;

        // space to decode the recipients bech32 identity
        var identity_buf: [bech32_max_len]u8 = undefined;

        // base64 encoded ephemeral share
        // to be written to the reciepient
        var ephemeral_share_b64: [43]u8 = undefined;

        // the encrypted file key to be base64
        // encoded and written to the reciepient
        var body: [32]u8 = undefined;
        var body_b64: [43]u8 = undefined;

        const Bech32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);
        _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);

        self.public_key = try X25519.recoverPublicKey(x25519_secret_key);

        // TODO: we'll assume no issues for now
        _ = std.os.linux.getrandom(
            &ephemeral_secret,
            ephemeral_secret.len,
            0x0002 // GRND_RANDOM
        );

        self.ephemeral_share = try X25519.scalarmult(ephemeral_secret, X25519.Curve.basePoint.toBytes());
        var shared_secret = try X25519.scalarmult(ephemeral_secret, self.public_key.?);
        defer std.crypto.utils.secureZero(u8, &shared_secret);

        @memcpy(salt[0..32], &self.ephemeral_share);
        @memcpy(salt[32..], &self.public_key.?);

        const k = hkdf.extract(&salt, &shared_secret);
        hkdf.expand(&key, key_label, k);

        ChaCha20Poly1305.encrypt(&ciphertext, &tag, file_key, &ad, nonce, key);

        @memcpy(body[0..16], &ciphertext);
        @memcpy(body[16..], &tag);

        const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);
        _ = encoder.encode(&body_b64, &body);
        _ = encoder.encode(&ephemeral_share_b64, &self.ephemeral_share);

        self.deinit(allocator);

        self.type      = try allocator.dupe(u8, x25519_recipient_type);
        self.args      = try allocator.alloc([]u8, 1);
        self.args.?[0] = try allocator.dupe(u8, &ephemeral_share_b64);
        self.body      = try allocator.dupe(u8, &body_b64);
        self.state     = .wrapped;

    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.type) |_type| {
            allocator.free(_type);
        }
        if (self.body) |body| {
            allocator.free(body);
        }
        if (self.args) |args| {
            for (args) |arg| { allocator.free(arg); }
            allocator.free(args);
        }
        self.type = null;
        self.body = null;
        self.args = null;
    }
};


test "unwrap" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    var recipient: Recipient = .{
        .type = try allocator.dupe(u8, "X25519"),
        .args = try allocator.alloc([]u8, 1),
        .body = try allocator.dupe(u8, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc");
    try recipient.init();
    defer recipient.deinit(allocator);

    try t.expect(recipient.state == .initialized);

    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    const file_key = try recipient.unwrap(allocator, identity);
    defer allocator.free(file_key);

    try t.expect(recipient.state == .unwrapped);
    try t.expectEqualSlices(u8, file_key, "YELLOW SUBMARINE");
}

test "wrap" {
    const t = std.testing;
    const mem = std.mem;
    const allocator = std.testing.allocator;

    var recipient: Recipient = .{
        .type = try allocator.dupe(u8, "X25519"),
        .args = try allocator.alloc([]u8, 1),
        .body = try allocator.dupe(u8, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc");

    try recipient.init();
    defer recipient.deinit(allocator);

    try t.expect(recipient.state == .initialized);

    const file_key = "YELLOW SUBMARINE";
    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    try recipient.wrap(allocator, file_key, identity);

    try t.expect(recipient.state == .wrapped);

    try t.expect(!mem.eql(u8, recipient.args.?[0], "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc"));
    try t.expect(!mem.eql(u8, recipient.body.?, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"));
}
