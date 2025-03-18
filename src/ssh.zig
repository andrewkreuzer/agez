const std = @import("std");
const exit = std.posix.exit;
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;

const Key = @import("key.zig").Key;
const Rsa = @import("ssh/rsa.zig");
const Recipient = @import("recipient.zig").Recipient;
const Parser = @import("ssh/lib.zig").Parser;
const PemDecoder = @import("ssh/lib.zig").PemDecoder;

pub const ed25519_stanza_arg = "ssh-ed25519";
pub const rsa_stanza_arg = "ssh-rsa";
const ed25519_key_label = "age-encryption.org/v1/ssh-ed25519";
const rsa_key_label = "age-encryption.org/v1/ssh-rsa";

pub const rsa = struct {
    pub fn toStanza(allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
        var buf: [109]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try std.fmt.format(
            writer,
        \\-> ssh-rsa {s} {s}
        \\{s}
        ,.{args[0], args[1], body}
        );
        return try allocator.dupe(u8, &buf);
    }

    pub fn fromPublicKey(allocator: Allocator, pk: Rsa.PublicKey, file_key: Key) !Recipient {
        // var r = Recipient{ .type = .rsa };
        // try r.wrap(allocator, file_key, pk);
        // return r;
        return wrap(allocator, file_key, pk);
    }

    pub fn unwrap(allocator: Allocator, private_key: Rsa.SecretKey, args: [][]u8, body: []u8) !Key {
        _ = args;

        var Decoder = PemDecoder{};
        var out_buf: [PemDecoder.max_key_size]u8 = undefined;
        const b = try Decoder.decode_no_pad(&out_buf, body);

        const file_key: Key = .{
            .slice = .{ .k = try allocator.alloc(u8, 16) }
        };
        try private_key.decryptOAEP(file_key.slice.k, b, rsa_key_label);

        return file_key;
    }

    pub fn wrap(allocator: Allocator, file_key: Key, public_key: Rsa.PublicKey) !Recipient {
        _ = allocator;
        _ = public_key;
        _ = file_key;
        var r = Recipient{ .type = .rsa };
        _ = &r;
        return r;
    }
};

pub const ed25519 = struct {
    pub fn toStanza(allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
        var buf: [109]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const writer = fbs.writer();

        try std.fmt.format(
            writer,
        \\-> ssh-ed25519 {s} {s}
        \\{s}
        ,.{args[0], args[1], body}
        );

        return try allocator.dupe(u8, &buf);
    }

    pub fn fromPublicKey(allocator: Allocator, pk: []const u8, file_key: Key) !Recipient {
        var r = Recipient{ .type = .@"ssh-ed25519" };
        try r.wrap(allocator, file_key, pk);
        return r;
    }


    /// Decrypts the recipients body and returns the file key
    pub fn unwrap(allocator: Allocator, private_key: []const u8, args: [][]u8, body: []u8) !Key {
        // derived from the shared secret and salt
        // decrypts the file key from the recipients body
        var key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &key);

        // the shortened fingerprint of the recipients public key
        var rpk_ssh_tag: [4]u8 = undefined;

        // the recipients ssh public key
        var epk: [32]u8 = undefined;

        // the encrypted file key
        var file_key_enc: [32]u8 = undefined;

        // the identities public key formatted for ssh
        var pk_ssh: [51]u8 = undefined;

        // the sha256 digest of the ssh public key
        var pk_ssh_tag: [Sha256.digest_length]u8 = undefined;

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

        if (args.len != 2) {
            return error.InvalidRecipientArgs;
        }

        const Decoder = std.base64.standard_no_pad.Decoder;
        Decoder.decode(&rpk_ssh_tag, args[1]) catch {
            return error.InvalidSshArgument;
        };
        Decoder.decode(&epk, args[0]) catch {
            return error.InvalidSshArgument;
        };
        Decoder.decode(&file_key_enc, body) catch {
            return error.InvalidSshBody;
        };

        const pk = private_key[32..64];
        try Parser.ed25519SshFormat(&pk_ssh, pk);
        Sha256.hash(&pk_ssh, &pk_ssh_tag, .{});
        if (!mem.eql(u8, &rpk_ssh_tag, pk_ssh_tag[0..4])) {
            return error.InvalidSshFingerprint;
        }

        var rk_hash: [Sha512.digest_length]u8 = undefined;
        Sha512.hash(private_key[0..32], &rk_hash, .{});
        const rk: [32]u8 = rk_hash[0..32].*;
        defer std.crypto.utils.secureZero(u8, &rk_hash);

        const rpk = try X25519.recoverPublicKey(rk);

        var shared_secret = blk: {
            var tweak: [32]u8 = undefined;
            hkdf.expand(
                &tweak,
                ed25519_key_label,
                hkdf.extract(&pk_ssh, &[_]u8{})
            );
            break :blk try X25519.scalarmult(
                       tweak,
                       try X25519.scalarmult(rk, epk)
                   );
               };
        defer std.crypto.utils.secureZero(u8, &shared_secret);

        @memcpy(salt[0..32], &epk);
        @memcpy(salt[32..], &rpk);

        const k = hkdf.extract(&salt, &shared_secret);
        hkdf.expand(&key, ed25519_key_label, k);

        const tag_start = file_key_enc.len - ChaCha20Poly1305.tag_length;
        @memcpy(&tag, file_key_enc[tag_start..]);

        const payload = file_key_enc[0..tag_start];
        const file_key: Key = .{
            .slice = .{ .k = try allocator.alloc(u8, payload.len), }
        };

        try ChaCha20Poly1305.decrypt(file_key.slice.k, payload, tag, &ad, nonce, key);

        return file_key;
    }

    /// Encrypts the file key in the recipients body
    /// and populates the recipients type, args, and body
    /// caller is responsible for deinit on the reciepient
    pub fn wrap(allocator: Allocator, file_key: Key, public_key: []const u8) !Recipient {
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

        // the public key formatted for ssh
        var pk_ssh: [51]u8 = undefined;

        // base64 encoded public key
        // to be written to the reciepient
        var epk_b64: [43]u8 = undefined;

        // the sha256 digest of the ssh public key
        var pk_tag: [Sha256.digest_length]u8 = undefined;

        // the sha256 digest of the ssh public key
        var ssh_tag_b64: [6]u8 = undefined;

        // derived from the ephemeral share
        // and the recipients public key
        var salt: [64]u8 = undefined;

        // a blank nonce
        const nonce = [_]u8{0x00} ** 12;

        // an empty associated data
        const ad = [_]u8{};

        // tag returned from ChaCha20Poly1305
        var tag: [16]u8 = undefined;

        // the encrypted file key base64 encoded
        var body: [43]u8 = undefined;

        _ = std.os.linux.getrandom(
            &ephemeral_secret,
            ephemeral_secret.len,
            0x0002 // GRND_RANDOM
        );

        const epk = try X25519.recoverPublicKey(ephemeral_secret);
        const rpk = blk: {
            const rpk_ed = try std.crypto.ecc.Edwards25519.fromBytes(public_key[0..32].*);
            const rpk_x = try X25519.Curve.fromEdwards25519(rpk_ed);
            break :blk rpk_x.toBytes();
        };

        try Parser.ed25519SshFormat(&pk_ssh, public_key);
        Sha256.hash(&pk_ssh, &pk_tag, .{});

        var shared_secret = blk: {
            var tweak: [32]u8 = undefined;
            hkdf.expand(
                &tweak,
                ed25519_key_label,
                hkdf.extract(&pk_ssh, &[_]u8{})
            );
            break :blk try X25519.scalarmult(
                       tweak,
                       try X25519.scalarmult(ephemeral_secret, rpk)
                   );
               };
        defer std.crypto.utils.secureZero(u8, &shared_secret);

        @memcpy(salt[0..32], &epk);
        @memcpy(salt[32..], &rpk);

        const k = hkdf.extract(&salt, &shared_secret);
        hkdf.expand(&key, ed25519_key_label, k);

        ChaCha20Poly1305.encrypt(file_key_enc[0..16], &tag, file_key.key().bytes, &ad, nonce, key);

        @memcpy(file_key_enc[16..], &tag);

        const Encoder = std.base64.standard_no_pad.Encoder;
        _ = Encoder.encode(&body, &file_key_enc);
        _ = Encoder.encode(&ssh_tag_b64, pk_tag[0..4]);
        _ = Encoder.encode(&epk_b64, &epk);

        var args = try allocator.alloc([]u8, 2);
        args[0] = try allocator.dupe(u8, &ssh_tag_b64);
        args[1] = try allocator.dupe(u8, &epk_b64);

        return .{
            .type = .@"ssh-ed25519",
            .args = args,
            .body = try allocator.dupe(u8, &body),
        };
    }
};

const SshErrors = error{
    InvalidSshFingerprint,
    InvalidSshArgument,
    InvalidSshBody,
};
