const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;

const Key = @import("key.zig").Key;
const X25519 = @import("X25519.zig");
const scrypt = @import("scrypt.zig");

pub const Recipient = struct {
    const Self = @This();
    const stanza_prefix = "-> ";

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

        pub fn fromString(s: []const u8) !@This() {
            if (std.mem.eql(u8, s, "X25519")) {
                return .X25519;
            } else if (std.mem.eql(u8, s, "scrypt")) {
                return .scrypt;
            } else return error.InvalidRecipientType;
        }

        fn toString(self: @This(), allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
            switch (self) {
                .X25519 => return try X25519.toString(allocator, args, body),
                .scrypt => return try scrypt.toString(allocator, args, body),
            }
        }

        fn unwrap(self: @This(), allocator: Allocator, identity: []const u8, args: [][]u8, body: []u8) !Key {
            switch (self) {
                .X25519 => return try X25519.unwrap(allocator, identity, args, body),
                .scrypt => return try scrypt.unwrap(allocator, identity, args, body),
            }
        }

        fn wrap(self: @This(), allocator: Allocator, file_key: Key, key: []const u8) !Recipient {
            return switch (self) {
                .X25519 => try X25519.wrap(allocator, file_key, key),
                .scrypt => try scrypt.wrap(allocator, file_key, key),
            };
        }
    };

    /// returns the stanza of a recipient. it's the
    /// callers responsibility to free the memory
    pub fn toString(self: *Self, allocator: Allocator) ![]const u8 {
        return self.type.toString(allocator, self.args.?, self.body.?);
    }

    /// Decrypts the file key from the recipients body
    /// it is the callers responsibility to ensure safety
    /// and deallocation of the decrypted file key
    pub fn unwrap(self: *Self, allocator: Allocator, identity: []const u8) !Key {
        self.state = .unwrapped;
        return self.type.unwrap(allocator, identity, self.args.?, self.body.?);
    }

    /// Encrypts the file key in the recipients body
    /// and populates the recipients type, args, and body
    /// caller is responsible for deinit on the reciepient
    pub fn wrap(self: *Self, allocator: Allocator, file_key: Key, key: []const u8) !void {
        var new_recipient =  try self.type.wrap(allocator, file_key, key);
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
    InvalidRecipientArgs
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

    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    var file_key = try recipient.unwrap(allocator, identity);
    defer file_key.deinit(allocator);

    try t.expect(recipient.state == .unwrapped);
    try t.expectEqualSlices(u8, file_key.key(), "YELLOW SUBMARINE");
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

    var file_key = Key{ .k = try allocator.dupe(u8, "YELLOW SUBMARINE") };
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
