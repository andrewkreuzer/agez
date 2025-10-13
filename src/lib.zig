const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const age = @import("age.zig");
pub const bech32 = @import("bech32.zig");
pub const ssh = @import("ssh/lib.zig");
pub const X25519 = @import("X25519.zig");
pub const AgeIo = @import("Io.zig");
pub const AgeReader = format.Reader;
pub const AgeWriter = format.Writer;
pub const Key = @import("key.zig").Key;
pub const Recipient = @import("recipient.zig").Recipient;

const armor = @import("armor.zig");
const format = @import("format.zig");
const Header = age.Header;

const RecipientList = ArrayList(Recipient);

pub const AgeEncryptor = struct {
    const Self = @This();

    allocator: Allocator,
    input: *Io.Reader,
    output: *Io.Writer,

    pub fn init(
        allocator: Allocator,
        reader: *Io.Reader,
        writer: *Io.Writer
    ) Self {
        return .{
            .allocator = allocator,
            .input = reader,
            .output = writer,
        };
    }

    pub fn encrypt(
        self: Self,
        file_key: *const Key,
        recipients: RecipientList,
        armored: bool
    ) !void {
        const header: Header = .{
            .version = .v1,
            .recipients = recipients,
            .allocator = self.allocator
        };
        var armored_buf: [4096]u8 = undefined;
        var w: AgeWriter = .init(self.allocator, self.output, armored, &armored_buf);

        if (armored)
            try w.armored_writer.begin();

        try w.write(file_key, header);
        try age.encrypt(file_key, self.input, w.output);

        if (armored)
            try w.armored_writer.finish();

    }
};

pub const AgeDecryptor = struct {
    const Self = @This();

    allocator: Allocator,
    input: *Io.Reader,
    output: *Io.Writer,

    pub fn init(
        allocator: Allocator,
        reader: *Io.Reader,
        writer: *Io.Writer
    ) Self {
        return .{
            .allocator = allocator,
            .input = reader,
            .output = writer
        };
    }

    pub fn decrypt(self: Self, identities: []Key) !void {
        var armored_buffer: [1024]u8 = undefined;
        var reader: AgeReader = .init(
            self.allocator, self.input, &armored_buffer
        );

        var header = try reader.parse();
        defer header.deinit(self.allocator);

        const file_key: Key = try header.unwrap(self.allocator, identities);
        defer file_key.deinit(self.allocator);

        try header.verify_hmac(&file_key);

        try age.decrypt(&file_key, &reader, self.output);
    }
};

test {
    _  = age;
    _ = format;
    _ = bech32;
    _ = armor;
    _ = @import("recipient.zig");
    _ = @import("ssh/rsa.zig");
}
