const builtin = @import("builtin");
const std = @import("std");
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
        X25519,
        scrypt,
        @"ssh-ed25519",
        rsa,

        pub fn fromStanzaArg(s: []const u8) !@This() {
            if (std.mem.eql(u8, s, X25519.stanza_arg)) {
                return .X25519;
            } else if (std.mem.eql(u8, s, scrypt.stanza_arg)) {
                return .scrypt;
            } else if (std.mem.eql(u8, s, ssh.ed25519_stanza_arg)) {
                return .@"ssh-ed25519";
            } else if (std.mem.eql(u8, s, ssh.rsa_stanza_arg)) {
                return .rsa;
            } else return error.InvalidRecipientType;
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
        switch (key) {
            .ed25519 => |ed25519| return try ssh.ed25519.fromPublicKey(allocator, &ed25519.public_key.bytes, file_key),
            .rsa => |rsa| return try ssh.rsa.fromPublicKey(allocator, rsa.public_key, file_key),
            else => return error.FromKeyNotSupported,
        }
    }

    /// returns the stanza of a recipient. it's the
    /// callers responsibility to free the memory
    pub fn toStanza(self: *Self, allocator: Allocator) ![]const u8 {
        switch (self.type) {
            .X25519 => return try X25519.toStanza(allocator, self.args.?, self.body.?),
            .scrypt => return try scrypt.toStanza(allocator, self.args.?, self.body.?),
            .@"ssh-ed25519" => return try ssh.ed25519.toStanza(allocator, self.args.?, self.body.?),
            .rsa => return try ssh.rsa.toStanza(allocator, self.args.?, self.body.?),
        }
    }

    /// Decrypts the file key from the recipients body
    /// it is the callers responsibility to ensure safety
    /// and deallocation of the decrypted file key
    pub fn unwrap(self: *Self, allocator: Allocator, identity: Key) !Key {
        self.state = .unwrapped;
        switch (self.type) {
            .X25519 => return try X25519.unwrap(allocator, identity.key().bytes, self.args.?, self.body.?),
            .scrypt => return try scrypt.unwrap(allocator, identity.key().bytes, self.args.?, self.body.?),
            .@"ssh-ed25519" => return try ssh.ed25519.unwrap(allocator, identity.key().bytes, self.args.?, self.body.?),
            .rsa => return try ssh.rsa.unwrap(allocator, identity.key().rsa.private_key, self.args.?, self.body.?),
        }
    }

    /// Encrypts the file key in the recipients body
    /// and populates the recipients type, args, and body
    /// caller is responsible for deinit on the reciepient
    pub fn wrap(self: *Self, allocator: Allocator, file_key: Key, key: Key) !void {
        var new_recipient = switch (self.type) {
            .X25519 => try X25519.wrap(allocator, file_key, key),
            .scrypt => try scrypt.wrap(allocator, file_key, key),
            .@"ssh-ed25519" => try ssh.ed25519.wrap(allocator, file_key, key),
            .rsa => try ssh.rsa.wrap(allocator, file_key, key.rsa.public_key),
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

test "unwrap" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    var recipient: Recipient = .{
        .type = .X25519,
        .args = try allocator.alloc([]u8, 1),
        .body = try allocator.dupe(u8, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc");
    defer recipient.deinit(allocator);

    var identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6".*;
    const id: Key = .{ .slice = .{ .k = &identity } };
    var file_key = try recipient.unwrap(allocator, id);
    defer file_key.deinit(allocator);

    try t.expect(recipient.state == .unwrapped);
    try t.expectEqualSlices(u8, file_key.key().bytes, "YELLOW SUBMARINE");
}

test "wrap" {
    const t = std.testing;
    const mem = std.mem;
    const allocator = std.testing.allocator;
    const bech32 = @import("bech32.zig");

    var recipient: Recipient = .{
        .type = .X25519,
        .args = try allocator.alloc([]u8, 1),
        .body = try allocator.dupe(u8, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"),
    };
    recipient.args.?[0] = try allocator.dupe(u8, "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc");

    defer recipient.deinit(allocator);

    var file_key: Key = .{ .slice = .{ .k = try allocator.dupe(u8, "YELLOW SUBMARINE") } };
    defer file_key.deinit(allocator);

    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    var identity_buf: [X25519.bech32_max_len]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, X25519.bech32_hrp_private, identity);
    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try std.crypto.dh.X25519.recoverPublicKey(x25519_secret_key);

    try recipient.wrap(allocator, file_key, &public_key);

    try t.expect(recipient.state == .wrapped);

    try t.expect(!mem.eql(u8, recipient.args.?[0], "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc"));
    try t.expect(!mem.eql(u8, recipient.body.?, "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U"));
}
