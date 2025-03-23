const builtin = @import("builtin");
const std = @import("std");
const io = std.io;
const Allocator = std.mem.Allocator;

const Key = @import("key.zig").Key;
const KeyType = @import("key.zig").KeyType;
const X25519 = @import("X25519.zig");
const scrypt = @import("scrypt.zig");
const ssh = @import("ssh.zig");

pub const Recipient = struct {
    const Self = @This();

    type: Type,
    args: ?[][]u8 = null,
    body: ?[]u8 = null,
    state: State = .none,

    const State = enum {
        unwrapped,
        wrapped,
        none,
    };

    pub const Type = enum {
        scrypt,
        X25519,
        @"ssh-rsa",
        @"ssh-ed25519",

        pub fn fromStanzaArg(s: []const u8) !@This() {
            const fields = @typeInfo(Type).@"enum".fields;
            inline for (fields) |field| {
                if (std.mem.eql(u8, s, field.name)) {
                    return @enumFromInt(field.value);
                }
            }
            return error.InvalidRecipientType;
        }
    };

    pub fn fromPassphrase(allocator: Allocator, passphrase: []const u8, file_key: Key) !Self {
        return try scrypt.fromPassphrase(allocator, passphrase, file_key);
    }

    pub fn fromAgePublicKey(allocator: Allocator, s: []const u8, file_key: Key) !Self {
        return try X25519.fromPublicKey(allocator, s, file_key);
    }

    pub fn fromAgePrivateKey(allocator: Allocator, s: []const u8, file_key: Key) !Self {
        return try X25519.fromPrivateKey(allocator, s, file_key);
    }

    pub fn fromSshKey(allocator: Allocator, key: Key, file_key: Key) !Self {
        return switch (key) {
            .ed25519 => |ed25519| try ssh.ed25519.fromPublicKey(allocator, &ed25519.public_key.bytes, file_key),
            .rsa => |rsa| try ssh.rsa.fromPublicKey(allocator, rsa.public_key, file_key),
            else => error.FromKeyNotSupported,
        };
    }

    /// returns the stanza of a recipient. it's the
    /// callers responsibility to free the memory
    pub fn toStanza(self: *Self, allocator: Allocator) ![]const u8 {
        return switch (self.type) {
            .X25519 => try X25519.toStanza(allocator, self.args.?, self.body.?),
            .scrypt => try scrypt.toStanza(allocator, self.args.?, self.body.?),
            .@"ssh-ed25519" => try ssh.ed25519.toStanza(allocator, self.args.?, self.body.?),
            .@"ssh-rsa" => try ssh.rsa.toStanza(allocator, self.args.?, self.body.?),
        };
    }

    /// Decrypts the file key from the recipients body
    /// it is the callers responsibility to ensure safety
    /// and deallocation of the decrypted file key
    pub fn unwrap(self: *Self, allocator: Allocator, identity: Key) !Key {
        self.state = .unwrapped;
        return switch (self.type) {
            .X25519 => try X25519.unwrap(allocator, identity.key().bytes, self.args.?, self.body.?),
            .scrypt => try scrypt.unwrap(allocator, identity.key().bytes, self.args.?, self.body.?),
            .@"ssh-ed25519" => try ssh.ed25519.unwrap(allocator, identity.key().bytes, self.args.?, self.body.?),
            .@"ssh-rsa" => try ssh.rsa.unwrap(allocator, identity.key().rsa.private_key, self.args.?, self.body.?),
        };
    }

    /// Encrypts the file key in the recipients body
    /// and populates the recipients type, args, and body
    /// caller is responsible for deinit on the reciepient
    pub fn wrap(self: *Self, allocator: Allocator, file_key: Key, key: Key) !void {
        var new_recipient = switch (self.type) {
            .X25519 => try X25519.wrap(allocator, file_key, key),
            .scrypt => try scrypt.wrap(allocator, file_key, key),
            .@"ssh-ed25519" => try ssh.ed25519.wrap(allocator, file_key, key),
            .@"ssh-rsa" => try ssh.rsa.wrap(allocator, file_key, key.rsa.public_key),
        };
        new_recipient.state = .wrapped;
        std.mem.swap(Self, self, &new_recipient);
        new_recipient.deinit(allocator);
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.body) |body| { allocator.free(body); }
        if (self.args) |args| {
            for (args) |arg| { allocator.free(arg); }
            allocator.free(args);
        }
        self.body = null;
        self.args = null;
    }
};

const RecipientErrors = error{
    InvalidRecipient,
    InvalidRecipientType,
    FromKeyNotSupported,
};

test "X25519 recipient" {
    const t = std.testing;
    const allocator = std.testing.allocator;
    const mem = std.mem;
    const bech32 = @import("bech32.zig");

    const test_file_key = "YELLOW SUBMARINE";
    var recipient: Recipient = .{
        .type = .X25519,
        .args = try allocator.alloc([]u8, 1),
        .body = try allocator.dupe(u8, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc");

    var identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6".*;
    const id: Key = .{ .slice = .{ .k = &identity } };
    var file_key = try recipient.unwrap(allocator, id);
    var identity_buf: [X25519.bech32_max_len]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, X25519.bech32_hrp_private, &identity);
    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try std.crypto.dh.X25519.recoverPublicKey(x25519_secret_key);

    try t.expect(recipient.state == .unwrapped);
    try t.expectEqualSlices(u8, file_key.key().bytes, test_file_key);

    const key = try Key.init(allocator, public_key);
    try recipient.wrap(allocator, file_key, key);

    try t.expect(recipient.state == .wrapped);

    try t.expect(!mem.eql(u8, recipient.args.?[0], "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc"));
    try t.expect(!mem.eql(u8, recipient.body.?, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"));

    file_key.deinit(allocator);
    key.deinit(allocator);
    recipient.deinit(allocator);
}

test "scrypt recipient" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    const test_file_key = "YELLOW SUBMARINE";
    var passphrase = "password".*;
    var recipient: Recipient = .{
        .type = .scrypt,
        .args = try allocator.alloc([]u8, 2),
        .body = try allocator.dupe(u8, "gUjEymFKMVXQEKdMMHL24oYexjE3TIC0O0zGSqJ2aUY"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "rF0/NwblUHHTpgQgRpe5CQ");
    recipient.args.?[1] = try allocator.dupe(u8, "10");

    const id: Key = .{ .slice = .{ .k = &passphrase } };
    var file_key = try recipient.unwrap(allocator, id);
    try t.expect(recipient.state == .unwrapped);
    try t.expectEqualSlices(u8, test_file_key, file_key.key().bytes);

    try recipient.wrap(allocator, file_key, id);
    try t.expect(recipient.state == .wrapped);

    file_key.deinit(allocator);
    recipient.deinit(allocator);
}

test "ed25519 recipient" {
    const SshParser = @import("ssh/lib.zig").Parser;
    const t = std.testing;
    const allocator = std.testing.allocator;

    const test_file_key = "YELLOW SUBMARINE";
    var private_key =
        \\-----BEGIN OPENSSH PRIVATE KEY-----
        \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        \\QyNTUxOQAAACDbG0rq7DpgTElpxU1kFWBYUm2vTut2QtLziCXnc3+qVgAAAJitCiUbrQol
        \\GwAAAAtzc2gtZWQyNTUxOQAAACDbG0rq7DpgTElpxU1kFWBYUm2vTut2QtLziCXnc3+qVg
        \\AAAEB1ovrGH8VhrZsp5G0UsHDrXjysoYiD4GhnPuIuuoUoidsbSursOmBMSWnFTWQVYFhS
        \\ba9O63ZC0vOIJedzf6pWAAAAEWFrcmV1emVyQGNhcm5haGFuAQIDBA==
        \\-----END OPENSSH PRIVATE KEY-----
        .*
    ;
    var recipient: Recipient = .{
        .type = .@"ssh-ed25519",
        .args = try allocator.alloc([]u8, 2),
        .body = try allocator.dupe(u8, "+Iil7T4RMV75FvQKvZD6gkjWsllUrW5SBHHxN2wMruw"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "xk+TSA");
    recipient.args.?[1] = try allocator.dupe(u8, "xSh4cYHalYztTjXKULvJhGWIEp8gCSIQ/zx13jGzalw");

    const id: Key = try SshParser.parseOpenSshPrivateKey(&private_key);
    var file_key = try recipient.unwrap(allocator, id);

    try t.expect(recipient.state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key().bytes);

    const pk: Key = try Key.init(allocator, id.ed25519.public_key.bytes);
    try recipient.wrap(allocator, file_key, pk);

    try t.expect(recipient.state == .wrapped);

    file_key.deinit(allocator);
    pk.deinit(allocator);
    recipient.deinit(allocator);
}

test "rsa recipient" {
    const SshParser = @import("ssh/lib.zig").Parser;
    const t = std.testing;
    const allocator = std.testing.allocator;

    const test_file_key = "YELLOW SUBMARINE";
    var private_key =
        \\-----BEGIN OPENSSH PRIVATE KEY-----
        \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
        \\NhAAAAAwEAAQAAAIEAuSa/Sk+MhHf5lv7Las1e83a86RlkPPqd7ttOT4ucZ/bV7oYdbQwo
        \\KdHVOUQJ8gcl9k0frPXR/qr/CX/dW87t/vy49lsGHsM3b+NQ4TmjkRkSvDJgK4rnM6dSZE
        \\Hy5UAWlmo1saQnLG06/Ui6/at6F2gaNNlFHSjwvOruKCUnRlUAAAIAWlA1kFpQNZAAAAAH
        \\c3NoLXJzYQAAAIEAuSa/Sk+MhHf5lv7Las1e83a86RlkPPqd7ttOT4ucZ/bV7oYdbQwoKd
        \\HVOUQJ8gcl9k0frPXR/qr/CX/dW87t/vy49lsGHsM3b+NQ4TmjkRkSvDJgK4rnM6dSZEHy
        \\5UAWlmo1saQnLG06/Ui6/at6F2gaNNlFHSjwvOruKCUnRlUAAAADAQABAAAAgFmqzTt02Q
        \\2SePrKfMNFoLVyDL0rAeOSUAhMh1l4uI+U+DhjFT8pgw31xDjOna5sDdOBuFRwXHnkYE0+
        \\cnqy9YkTIyqLz+O1WPwJrX8xHY4KnYBAkhsXvJnmhSxJZM/9IJztBLyzwTuI3sRUcJ15S5
        \\IlI3YKM2fBMkMTa6Sah+clAAAAQQDL+BSk78zrQfel/enOosLombu6LFHDD79TToz+cFBG
        \\AE8RKtpRDwp9ZGbQ/wjKmETU8F81V+YmJ8ZKdGGVRcBDAAAAQQDuk4nzpOcvy0cCHzphaY
        \\DDb9RvHCSIENE6JjhiaVNfPKzGJcrEucsGA8q1KYJPqstorMWsPwEORMFygX61fvJfAAAA
        \\QQDGrF3ac2jIh7WU++00o3lsGm7rqhQUNJ63nHDMgFbo65OIk55PGT5x+yNayRy/Z92gvQ
        \\KITxCvrdPBzRqxzQvLAAAABGFnZXoBAgMEBQY=
        \\-----END OPENSSH PRIVATE KEY-----
        .*
    ;
    const id = try SshParser.parseOpenSshPrivateKey(&private_key);
    var recipient: Recipient = .{
        .type = .@"ssh-rsa",
        .args = try allocator.alloc([]u8, 1),
        .body = try allocator.dupe(u8, 
            \\AmzFOlub++Nsaxhme3ynSwrSjYZwYIyt91m2+CXZnkOGDMurW8vVyERWQZRQxB5j
            \\c9KVBe+MhHGt8zMjhytnjepioA4bCJgnxLUKU4u8WzH68TbCFb5wcoiNkTVOejyy
            \\NGV+DSwX6vBCzxsaswpYFbhG0X6wzYweUqJgvovYW/k
        ),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "UI4tAQ");

    var file_key = try recipient.unwrap(allocator, id);

    try t.expect(recipient.state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key().bytes);

    try recipient.wrap(allocator, file_key, id);

    try t.expect(recipient.state == .wrapped);

    file_key.deinit(allocator);
    recipient.deinit(allocator);
}
