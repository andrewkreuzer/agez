const std = @import("std");
const Allocator = std.mem.Allocator;
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;
const ArrayList = std.ArrayList;

pub const age = @import("age.zig");
const Header = age.Header;
const armor = @import("armor.zig");
pub const bech32 = @import("bech32.zig");
pub const cli = @import("cli.zig");
const Args = cli.Args;
const format = @import("format.zig");
pub const AgeReader = format.AgeReader;
pub const AgeWriter = format.AgeWriter;
pub const Io = @import("io.zig");
pub const Key = @import("key.zig").Key;
pub const Recipient = @import("recipient.zig").Recipient;
pub const ssh = @import("ssh/lib.zig");
pub const X25519 = @import("X25519.zig");

const RecipientList = ArrayList(Recipient);

pub fn AgeEncryptor(ReaderType: type, WriterType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        reader: ReaderType,
        writer: WriterType,

        pub fn init(allocator: Allocator, reader: ReaderType, writer: WriterType) Self {
            return .{
                .allocator = allocator,
                .reader = reader,
                .writer = writer,
            };
        }

        pub fn encrypt(
            self: Self,
            file_key: *const Key,
            recipients: RecipientList,
            armored: bool
        ) !void {
            const header: Header = .{ .version = .v1, .recipients = recipients };
            var writer = AgeWriter(WriterType).init(self.allocator, self.writer, armored);
            defer writer.deinit();

            try writer.write(file_key, header);

            _ = try age.encrypt(file_key, self.reader, writer.writer());
        }
    };

}

pub fn AgeDecryptor(ReaderType: type, WriterType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        reader: ReaderType,
        writer: WriterType,

        pub fn init(allocator: Allocator, reader: ReaderType, writer: WriterType) Self {
            return .{ .allocator = allocator, .reader = reader, .writer = writer, };
        }

        pub fn decrypt(
            self: Self,
            identities: []Key,
        ) !void {
            var reader = AgeReader(ReaderType).init(self.allocator, self.reader);
            defer reader.deinit();

            var header = try reader.parse();
            defer header.deinit(self.allocator);

            const file_key: Key = try header.unwrap(self.allocator, identities);
            defer file_key.deinit(self.allocator);

            try header.verify_hmac(&file_key);

            _ = try age.decrypt(&file_key, reader.reader(), self.writer);
        }
    };
}

test {
    _  = age;
    _  = cli;
    _ = format;
    _ = bech32;
    _ = armor;
    _ = @import("recipient.zig");
    _ = @import("ssh/rsa.zig");
}
