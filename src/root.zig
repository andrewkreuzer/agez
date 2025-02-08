const builtin = @import("builtin");
const std = @import("std");
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const File = std.fs.File;
const exit = std.process.exit;

const format = @import("format.zig");
const bech32 = @import("bech32.zig");

pub fn run() !void {
    const file = try std.fs.cwd().openFile("testkit/x25519", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const file_data = format.fromFile(allocator, file) catch |err| {
        std.debug.print("Error: {any}\n", .{err});
        exit(1);
    };

    const mac = file_data.mac[0..file_data.mac_len];
    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    var file_key: [16]u8 = undefined;
    try fileKeyFromStanze(&file_key, identity, file_data.recipients[0]);

    if (!try verify_hmac(file_key[0..16], file_data.header_bytes[0..file_data.header_len], mac)) {
        std.debug.print("hmac mismatch\n", .{});
    }

    var data: [64]u8 = undefined;
    try decryptPayload(&data, file_key[0..16], file_data.payload);

    std.debug.print("data: {s}\n", .{data[0..3]});

    var tag: [16]u8 = undefined;
    var ciphertext: [64]u8 = undefined;
    const message = "yoo";
    const n = encryptPayload(&tag, &ciphertext, message, file_key[0..16]);

    var test_data: [64]u8 = undefined;
    try decryptPayload(&test_data, &file_key, ciphertext[0..n]);

    std.debug.print("msg: {s}\n", .{test_data[0..3]});

    var stanza: [92]u8 = undefined;
    try stanzaFromFileKey(&stanza, &file_key, identity);

    var tag2: [64]u8 = undefined;
    @memcpy(tag2[0..6], stanza[0..6]);
    const args: []format.Arg = format.toArgs(stanza[6..49]);
    const test_recipient: format.Recipient = .{
        .tag = tag2,
        .args = args,
        .body = stanza[49..],
    };

    var file_key2: [16]u8 = undefined;
    try fileKeyFromStanze(&file_key2, identity, test_recipient);

    std.debug.print("file_key2: {s}\n", .{file_key2});
}

fn encryptPayload(tag: *[16]u8, ciphertext: []u8, m: []const u8, key: []const u8) usize {
    var key_nonce: [16]u8 = undefined;
    _ = std.os.linux.getrandom(&key_nonce, key_nonce.len, 0x0002); // we'll assume no issues for now, GRND_RANDOM

    const payload_key = hkdf.extract(&key_nonce, key);
    var enc_key: [32]u8 = undefined;
    hkdf.expand(&enc_key, "payload", payload_key);

    const ad = [_]u8{};
    var out: [12]u8 = undefined;
    
    var nonce = [_]u8{0x00} ** 12;
    nonce[nonce.len-1] = 0x01; // assume we're on the last block, TODO: don't

    ChaCha20Poly1305.encrypt(out[0..m.len], tag, m, &ad, nonce, enc_key);

    @memcpy(ciphertext[0..key_nonce.len], &key_nonce);
    @memcpy(ciphertext[key_nonce.len..key_nonce.len+m.len], out[0..m.len]);
    @memcpy(ciphertext[key_nonce.len+m.len..key_nonce.len+m.len+tag.len], tag);

    return key_nonce.len + m.len + tag.len;
}

fn decryptPayload(m: []u8, key: []const u8, payload: []u8) !void {
    const nonce_end = 16;
    var salt: [16]u8 = undefined;
    @memcpy(&salt, payload[0..nonce_end]);
    const payload_key = hkdf.extract(&salt, key);
    var enc_key: [32]u8 = undefined;
    hkdf.expand(&enc_key, "payload", payload_key);

    // TODO: size has to be exact for auth to work
    var in: [3]u8 = undefined;
    var out: [3]u8 = undefined;
    var nonce = [_]u8{0x00} ** 12;

    var tag: [16]u8 = undefined;
    const tag_start = payload.len - ChaCha20Poly1305.tag_length;
    @memcpy(&tag, payload[tag_start..]);

    // assume we're on the last block
    // TODO: don't assume this
    nonce[nonce.len-1] = 0x01;
    
    const pl = payload[nonce_end..tag_start];
    @memcpy(in[0..pl.len], pl);


    const ad = [_]u8{};
    ChaCha20Poly1305.decrypt(&out, &in, tag, &ad, nonce, enc_key) catch |err| switch (err) {
        error.AuthenticationFailed => {
            std.debug.print("Authentication failed, cannot verify integrity\nCheck that in and out buffer are correctly sized\n", .{});
            std.crypto.stream.chacha.ChaCha20IETF.xor(&out, &in, 1, enc_key, nonce);
        },
        else => return err,
    };

    @memcpy(m[0..out.len], &out);
}

fn stanzaFromFileKey(out: []u8, file_key: []const u8, identity: []const u8) !void {
    var ephemeral_secret: [32]u8 = undefined;
    _ = std.os.linux.getrandom(&ephemeral_secret, ephemeral_secret.len, 0x0002); // we'll assume no issues for now, GRND_RANDOM

    const ephemeral_share = try X25519.scalarmult(ephemeral_secret, X25519.Curve.basePoint.toBytes());

    var identity_buf: [180]u8 = undefined;
    const b32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);
    var our_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&our_secret_key, b32.data, 5, 8, false);
    const our_public_key = try X25519.recoverPublicKey(our_secret_key);

    const shared_secret = try X25519.scalarmult(ephemeral_secret, our_public_key);

    var salt: [64]u8 = undefined;
    @memcpy(salt[0..32], &ephemeral_share);
    @memcpy(salt[32..], &our_public_key);
    const key = hkdf.extract(&salt, &shared_secret);
    var enc_key: [32]u8 = undefined;
    hkdf.expand(&enc_key, "age-encryption.org/v1/X25519", key);

    var ciphertext: [16]u8 = undefined;
    const ad = [_]u8{};
    const nonce = [_]u8{0x00} ** 12;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, file_key, &ad, nonce, enc_key);

    const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
    const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);

    var arg_value: [43]u8 = undefined;
    _ = encoder.encode(&arg_value, &ephemeral_share);

    var body: [32]u8 = undefined;
    @memcpy(body[0..16], &ciphertext);
    @memcpy(body[16..], &tag);
    var bodyb64: [43]u8 = undefined;
    _ = encoder.encode(&bodyb64, &body);

    var rec_tag: [64]u8 = undefined;
    @memcpy(rec_tag[0..6], "X25519");

    @memcpy(out[0..6], rec_tag[0..6]);
    @memcpy(out[6..49], &arg_value);
    @memcpy(out[49..], &bodyb64);
}

fn fileKeyFromStanze(out: []u8, identity: []const u8, recipient: format.Recipient) !void {
    const value = recipient.tag[0..6];
    if (std.mem.eql(u8, value, "X25519")) {
        const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
        const decoder = std.base64.Base64Decoder.init(base64_alphabet, null);
        var ephemeral_share: [32]u8 = undefined;
        try decoder.decode(&ephemeral_share, recipient.args[0].value[0..43]);

        var identity_buf: [180]u8 = undefined;
        const b32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);
        var our_secret_key: [32]u8 = undefined;
        _ = try bech32.convertBits(&our_secret_key, b32.data, 5, 8, false);
        const our_public_key = try X25519.recoverPublicKey(our_secret_key);

        const shared_secret = try X25519.scalarmult(our_secret_key, ephemeral_share);

        var salt: [64]u8 = undefined;
        @memcpy(salt[0..32], &ephemeral_share);
        @memcpy(salt[32..], &our_public_key);
        const key = hkdf.extract(&salt, &shared_secret);
        var enc_key: [32]u8 = undefined;
        hkdf.expand(&enc_key, "age-encryption.org/v1/X25519", key);

        var encrypted_file_key: [32]u8 = undefined;
        try decoder.decode(&encrypted_file_key, recipient.body);
        if (encrypted_file_key.len != 32) { return error.InvalidBodyLength; }

        var m: [16]u8 = undefined;
        const ad = [_]u8{};
        const nonce = [_]u8{0x00} ** 12;
        var tag: [16]u8 = undefined;
        const tag_start = encrypted_file_key.len - ChaCha20Poly1305.tag_length;
        @memcpy(&tag, encrypted_file_key[tag_start..]);

        // try ChaCha20Poly1305.decrypt(&m, encrypted_file_key[0..tag_start], tag, &ad, nonce, enc_key);
        ChaCha20Poly1305.decrypt(&m, encrypted_file_key[0..tag_start], tag, &ad, nonce, enc_key) catch |err| switch (err) {
        error.AuthenticationFailed => {
            std.debug.print("Authentication failed, cannot verify integrity, Check that in and out buffer are correctly sized\n", .{});
            std.crypto.stream.chacha.ChaCha20IETF.xor(&m, encrypted_file_key[0..tag_start], 1, enc_key, nonce);
        },
        else => return err,
    };

        @memcpy(out[0..16], &m);
    }
}

fn decode_stanza_test(identity: []const u8, recipient: format.Recipient) !void {
    const value = recipient.tag[0..6];
    if (std.mem.eql(u8, value, "X25519")) {
        const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
        const decoder = std.base64.Base64Decoder.init(base64_alphabet, null);
        var ephemeral_share: [32]u8 = undefined;
        try decoder.decode(&ephemeral_share, recipient.args[0].value[0..43]);

        var identity_buf: [180]u8 = undefined;
        const b32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);
        var our_secret_key: [32]u8 = undefined;
        _ = try bech32.convertBits(&our_secret_key, b32.data, 5, 8, false);
        const our_public_key = try X25519.recoverPublicKey(our_secret_key);

        const shared_secret = try X25519.scalarmult(our_secret_key, ephemeral_share);

        var salt: [64]u8 = undefined;
        @memcpy(salt[0..32], &ephemeral_share);
        @memcpy(salt[32..], &our_public_key);
        const key = hkdf.extract(&salt, &shared_secret);
        var enc_key: [32]u8 = undefined;
        hkdf.expand(&enc_key, "age-encryption.org/v1/X25519", key);

        var encrypted_file_key: [32]u8 = undefined;
        try decoder.decode(&encrypted_file_key, recipient.body);
        if (encrypted_file_key.len != 32) { return error.InvalidBodyLength; }

        var m: [32]u8 = undefined;
        const nonce = [_]u8{0x00} ** 12;
        std.crypto.stream.chacha.ChaCha20IETF.xor(&m, &encrypted_file_key, 1, enc_key, nonce);

        const file_key_hex = "59454c4c4f57205355424d4152494e45";
        var buf_file_key_hex: [16]u8 = undefined;
        const file_key = try std.fmt.hexToBytes(&buf_file_key_hex, file_key_hex);

        std.debug.print("stanza decode: {s} | {any}\n", .{
            m[0..16],
            std.mem.eql(u8, file_key, m[0..16]),
        });
    }
}

fn verify_hmac(file_key: []const u8, header: []const u8, mac: []const u8) !bool {
    const salt = [_]u8{};
    const key = hkdf.extract(&salt, file_key);
    var buf_hmac_key = [_]u8{0} ** 32;
    hkdf.expand(&buf_hmac_key, "header", key);

    var buf_header_hmac = [_]u8{0} ** 32;
    hmac.create(&buf_header_hmac, header, &buf_hmac_key);

    const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
    const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);

    var buf_encode = [_]u8{0} ** 64;
    const hmac_padded_len = encoder.calcSize(mac.len);
    const encoded = encoder.encode(buf_encode[0..hmac_padded_len], &buf_header_hmac);

    return std.mem.eql(u8, mac, encoded);
}

fn header_hmac_test(file_data: format.FileData) !void {
    const header_bytes = file_data.header_bytes[0..file_data.header_len];
    const mac = file_data.mac[0..file_data.mac_len];

    const file_key_hex = "59454c4c4f57205355424d4152494e45";
    var buf_file_key_hex: [16]u8 = undefined;
    const file_key = try std.fmt.hexToBytes(&buf_file_key_hex, file_key_hex);

    const salt = [_]u8{};
    const key = hkdf.extract(&salt, file_key);
    var buf_hmac_key = [_]u8{0} ** 32;
    hkdf.expand(&buf_hmac_key, "header", key);

    var buf_header_hmac = [_]u8{0} ** 32;
    hmac.create(&buf_header_hmac, header_bytes, &buf_hmac_key);

    const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
    const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);
    const decoder = std.base64.Base64Decoder.init(base64_alphabet, null);

    var buf_encode = [_]u8{0} ** 64;
    const hmac_padded_len = encoder.calcSize(mac.len);
    const encoded = encoder.encode(buf_encode[0..hmac_padded_len], &buf_header_hmac);

    var buf_decode: [128]u8 = undefined;
    // apparently it's always 32 but we'll still calculate
    const padding = try decoder.calcSizeForSlice(mac);
    const decoded = buf_decode[0..padding];
    try decoder.decode(decoded, mac);

    std.debug.print("compare: {any} | {any}\n", .{
        std.mem.eql(u8, mac, encoded),
        std.mem.eql(u8, decoded, &buf_header_hmac)
    });
}

fn bech32_test() !void {
    var identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6".*;
    const hrp = "AGE-SECRET-KEY-";
    const hrp_lower = "age-secret-key-";
    var b32_buf_decode: [180]u8 = undefined;
    const b32_decoded = try bech32.decode(&b32_buf_decode, hrp, &identity);

    var buf: [180]u8 = undefined;
    const b32_encoded = try bech32.encode(&buf, hrp_lower, b32_decoded.data);
    std.debug.print("encoded: {s}\n", .{b32_encoded});
    std.debug.print("identity: {s}\n", .{identity});
}

const ParseError = enum {
    InvalidHmac,
    InvalidBodyLength,
};

test {
    _ = format;
    _ = bech32;
}
