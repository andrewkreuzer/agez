const std = @import("std");
const assert = std.debug.assert;
const Ed25519 = std.crypto.sign.Ed25519;
const Rsa = @import("ssh/lib.zig").Rsa;
const Allocator = @import("std").mem.Allocator;

const Bytes = struct {
    k: []u8,
    pk: ?[]u8 = null,
};

const KeyType = enum {
    slice,
    ed25519,
    rsa,
};

// TODO: needs a refactor now that rsa is in spec
pub const Key = union(KeyType) {
    const Self = @This();

    slice: Bytes,
    ed25519: Ed25519.KeyPair,
    rsa: Rsa.KeyPair,

    /// Allocates a new Key
    /// suppoerted key types are:
    /// * []u8
    /// * Ed25519.KeyPair
    /// * Rsa.KeyPair
    /// * usize (generates a random key)
    pub fn init(allocator: Allocator, T: anytype) !Key {
        switch (@TypeOf(T)) {
            comptime_int, usize => return .{ .slice = .{ .k = try allocator.alloc(u8, T) }},
            [32]u8 => return .{ .slice = .{ .k = try allocator.dupe(u8, &T) }},
            []u8 => return .{ .slice = .{ .k = try allocator.dupe(u8, T) }},
            Ed25519.KeyPair => {
                const kp = try allocator.create(Ed25519.KeyPair);
                kp.* = T;
                const k: Key = .{ .ed25519 = kp.* };
                return k;
            },
            Rsa.KeyPair => return .{ .rsa = T },
            else => return error.UnsupportedKeyType,
        }
    }

    /// Deallocates a Key ensuring the key
    /// is zeroed before freeing the memory
    pub fn deinit(self: *const Self, allocator: Allocator) void {
        switch (self.*) {
            KeyType.slice => |*slice| {
                std.crypto.utils.secureZero(u8, slice.k);
                allocator.free(slice.k);
                if (slice.pk) |pk| { allocator.free(pk); }
            },
            else => {}, // TODO
        }
    }

    /// return a reference to the key
    pub fn key(self: *const Self) union(enum){bytes: []const u8, rsa: Rsa.KeyPair} {
        switch (self.*) {
            KeyType.slice => return .{ .bytes = self.slice.k },
            KeyType.ed25519 => return .{ .bytes = &self.ed25519.secret_key.bytes },
            KeyType.rsa => return .{ .rsa = self.rsa },
        }
    }

    /// return the public key
    pub fn public(self: *const Self) ![32]u8 {
        return self.slice.pk;
    }
};
