const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Allocator = mem.Allocator;
const AllocatorError = mem.Allocator.Error;
const ArrayList = std.ArrayList;

const age = @import("age.zig");
const armor = @import("armor.zig");
const Header = age.Header;
const Version = age.Version;
const ArmoredReader = armor.Reader;
const ArmoredWriter = armor.Writer;
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;
const RecipientType = Recipient.Type;

const FormatError = error{
    Unexpected,
    InvalidAscii,
    EmptyStanza,
    InvalidHeader,
    InvalidWhitespace,
    ScryptMultipleRecipients,
};

const Prefix = enum {
    const version_prefix = "age";
    const stanza_prefix = "-> ";
    const hmac_prefix = "---";

    armor_begin,
    version,
    stanza,
    hmac,
    end,
    whitespace,
    unknown,

    fn match(buf: []u8) Prefix {
        if (mem.eql(u8, buf, version_prefix)) {
            return .version;
        }
        if (mem.eql(u8, buf, stanza_prefix)) {
            return .stanza;
        }
        if (mem.eql(u8, buf, hmac_prefix)) {
            return .hmac;
        }
        return .unknown;
    }
};

pub const Reader = struct {
    const Self = @This();

    input: *Io.Reader,
    armored_reader: ArmoredReader,
    armored: bool = false,
    whitespace: bool = false,

    allocator: Allocator,

    pub fn init(allocator: Allocator, reader: *Io.Reader, buffer: []u8) Self {
        return .{
            .allocator = allocator,
            .input = reader,
            .armored_reader =.init(reader, buffer),
        };
    }

    const Iterator = struct {
        const Iter = @This();

        const MAX_HEADER_SIZE = 8192;
        const MAX_LINE_SIZE = 4096;

        r: *Io.Reader,
        end: usize = 0,
        line: usize = 0,
        header_writer: *Io.Writer,

        const Line = struct {
            prefix: Prefix = .unknown,
            bytes: []u8 = &.{},
        };

        /// Reads lines of the file,
        /// keeping track of the line number and header.
        fn next(iter: *Iter) !Line {
            var w: *Io.Writer = iter.header_writer;
            var r = iter.r;

            const line = r.peekDelimiterExclusive('\n') catch |err| switch (err) {
                error.EndOfStream => return .{ .prefix = .end},
                else => return err,
            };

            if (isWhiteSpace(line)) {
                r.toss(line.len + 1); // +1
                return .{ .prefix = Prefix.whitespace, .bytes = line, };
            }

            if (line.len < 3) {
                return .{ .prefix = Prefix.unknown, .bytes = line, };
            }

            if (try armor.isArmorBegin(line)) {
                return .{ .prefix = Prefix.armor_begin, .bytes = line, };
            }

            r.toss(line.len + 1); // +1 for \n
            iter.line += 1;
            iter.end += try w.write(line) + try w.write("\n");

            const prefix = line[0..3];
            return .{
                .prefix = Prefix.match(prefix),
                .bytes = line,
            };
        }

        /// Reads until the predicate returns false or EOF is reached.
        fn takeUntilFalseOrEof(iter: *Iter, pred: fn ([]u8) callconv(.@"inline") bool) ![]u8 {
            var w: *Io.Writer = iter.header_writer;
            var r = iter.r;

            const start = w.end;
            while (true) {
                const line = r.takeDelimiterExclusive('\n') catch |err| {
                    if (err == error.EndOfStream) return &.{};
                    return err;
                };

                iter.line += 1;
                iter.end += try w.write(line) + try w.write("\n");

                if (!pred(line)) return w.buffer[start..w.end - 1];
            }
        }
    };

    pub fn parse(self: *Self) !Header {
        var header_buf: [Iterator.MAX_HEADER_SIZE]u8 = undefined;
        var header_writer: Io.Writer = .fixed(&header_buf);
        var iter: Iterator = .{ .r = self.input, .header_writer = &header_writer };
        var header = Header.init(self.allocator);
        errdefer header.deinit(self.allocator);

        while (true) {
            var line = try iter.next();
            line: switch (line.prefix) {
                .whitespace => self.whitespace = true,
                .armor_begin => {
                    assert(!self.armored);
                    self.armored = true;
                    self.input = &self.armored_reader.interface;
                    iter.r = self.input;
                },
                .version => {
                    if (self.whitespace and !self.armored) return error.InvalidWhitespace;
                    header.version = Version.fromStr(line.bytes);
                },
                .stanza => {
                    const stanza = line.bytes[3..];
                    if (stanza.len == 0) return error.EmptyStanza;
                    for (stanza) |c| try isValidAscii(c);

                    var arg_iter = std.mem.splitScalar(u8, stanza, ' ');
                    var args: std.ArrayList([]u8) = .empty;
                    defer args.deinit(self.allocator);

                    const t = arg_iter.first();
                    const _type = try RecipientType.fromStanzaArg(t);
                    for (header.recipients.items) |r| {
                        if (r.type == .scrypt or _type == .scrypt) {
                            return error.ScryptMultipleRecipients;
                        }
                    }

                    while (arg_iter.next()) |arg| {
                        try args.append(self.allocator, try self.allocator.dupe(u8, arg));
                    }
                    errdefer for (args.items) |arg| self.allocator.free(arg);

                    const b = try iter.takeUntilFalseOrEof(isStanzaEnd);
                    const body = try self.allocator.dupe(u8, b);
                    errdefer self.allocator.free(body);

                    try header.recipients.append(self.allocator, .{
                        .type = _type,
                        .args = try args.toOwnedSlice(self.allocator),
                        .body = body,
                    });
                },
                .hmac => {
                    const start = Prefix.hmac_prefix.len + 1; // space
                    const bytes = line.bytes[start..];
                    if (bytes.len != 43) return error.InvalidHeader;
                    if (isWhiteSpace(bytes)) return error.InvalidHeader;
                    for (bytes) |b| isValidAscii(b) catch return error.InvalidHeader;
                    header.mac = try self.allocator.dupe(u8, bytes);
                    continue :line .end;
                },
                .end => {
                    const header_len = iter.end - header.mac.?.len - 2; // space
                    const header_bytes = header_writer.buffered()[0..header_len];
                    header.bytes = try self.allocator.dupe(u8, header_bytes);
                    return header;
                },
                else => return error.InvalidHeader,
            }
        }
    }

    // The valid subset of ascii for age strings is 33-126
    // but we include 32 (space) for convenience
    pub inline fn isValidAscii(c: u8) FormatError!void {
        if (c < 32 or c > 126) {
            return error.InvalidAscii;
        }
    }

    pub inline fn isWhiteSpace(line: []u8) bool {
        const whitespaceFn = std.ascii.isWhitespace;
        for (line) |b| {
            if (!whitespaceFn(b)) return false;
        }
        return true;
    }

    // TODO: validate trailing bits
    inline fn isStanzaEnd(line: []u8) bool {
        if (line.len < 64) return false;
        return true;
    }
};

pub const Writer = struct {
    const Self = @This();
    output: *Io.Writer,
    normal_writer: *Io.Writer,
    armored_writer: ArmoredWriter,
    armored: bool,
    allocator: Allocator,

    pub fn init(allocator: Allocator, w: *Io.Writer, armored: bool, buffer: []u8) Self {
        return .{
            .allocator = allocator,
            .output = w,
            .normal_writer = w,
            .armored_writer = .init(w, buffer),
            .armored = armored,
        };
    }

    pub fn write(self: *Self, fk: *const Key, header: Header) !void {
        self.output = if (self.armored) &self.armored_writer.interface else self.normal_writer;
        var buf: [Reader.Iterator.MAX_HEADER_SIZE]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);

        _ = try w.write(header.version.?.toString());
        _ = try w.write("\n");
        for (header.recipients.items) |*r| {
            const rstring = try r.toStanza(self.allocator);
            _ = try w.write(rstring);
            _ = try w.write("\n");
            self.allocator.free(rstring);
        }
        _ = try w.write("---");

        const mac = generate_hmac(w.buffered(), fk);
        _ = try w.write(" ");
        _ = try w.write(&mac);
        _ = try w.write("\n");
        _ = try self.output.write(w.buffered());
    }
};

pub fn generate_hmac(
    header: []const u8,
    fk: *const Key
) [43]u8 {
    const salt = [_]u8{};
    var buf_key: [32]u8 = undefined;
    var buf_hmac: [32]u8 = undefined;
    var buf_encode: [64]u8 = undefined;

    const k = hkdf.extract(&salt, fk.key().bytes);
    hkdf.expand(&buf_key, "header", k);
    hmac.create(&buf_hmac, header, &buf_key);

    const Encoder = std.base64.standard_no_pad.Encoder;
    _ = Encoder.calcSize(buf_hmac.len);
    const encoded = Encoder.encode(&buf_encode, &buf_hmac);

    return encoded[0..43].*;
}


test "age file" {
    const t = std.testing;
    const bech32 = @import("bech32.zig");
    const X25519 = std.crypto.dh.X25519;
    var r: Io.Reader = .fixed(
        \\age-encryption.org/v1
        \\-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
        \\EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U
        \\-> X25519 ajtqAvDEkVNr2B7zUOtq2mAQXDSBlNrVAuM/dKb5sT4
        \\0evrK/HQXVsQ4YaDe+659l5OQzvAzD2ytLGHQLQiqxg
        \\-> X25519 0qC7u6AbLxuwnM8tPFOWVtWZn/ZZe7z7gcsP5kgA0FI
        \\T/PZg76MmVt2IaLntrxppzDnzeFDYHsHFcnTnhbRLQ8
        \\--- UCthUMrk+aJCkWnzueb2xSnd/zj41r4CrMB5SUcz9nM
        \\
    );
    var identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6".*;
    const test_file_key = "YELLOW SUBMARINE";

    const allocator = std.testing.allocator;
    // var buffer: [ArmoredReader.MIN_BUFFER_SIZE]u8 = undefined;
    var reader: Reader = .init(allocator, &r, &.{});
    var header = try reader.parse();
    defer header.deinit(allocator);

    try t.expect(header.version.? == .v1);
    try t.expect(header.recipients.items.len == 3);
    try t.expect(header.mac.?.len == 43);

    try t.expect(header.recipients.items[0].type == .X25519);
    try t.expectEqualStrings("TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc", header.recipients.items[0].args.?[0]);
    try t.expectEqualStrings("EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U", header.recipients.items[0].body.?);

    const id: Key = .{ .slice = .{ .k = &identity } };
    var file_key = try header.recipients.items[0].unwrap(allocator, id);
    defer file_key.deinit(allocator);

    try t.expect(header.recipients.items[0].state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key().bytes);
    try header.verify_hmac(&file_key);


    var identity_buf: [90]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", &identity);

    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try X25519.recoverPublicKey(x25519_secret_key);

    const key = try Key.init(allocator, public_key);
    defer key.deinit(allocator);
    try header.recipients.items[0].wrap(allocator, file_key, key);

    try t.expect(header.recipients.items[0].state == .wrapped);
}

test "armored age file" {
    const t = std.testing;
    const bech32 = @import("bech32.zig");
    const X25519 = std.crypto.dh.X25519;
    var r: Io.Reader = .fixed(
        \\-----BEGIN AGE ENCRYPTED FILE-----
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBURWlGMHlwcXIrYnB2Y3FY
        \\TnlDVkpwTDdPdXdQZFZ3UEw3S1FFYkZET0NjCkVtRUNBRWNLTituL1ZzOVNiV2lW
        \\K0h1MHIrRThSNzdEZFdZeWQ4M253N1UKLS0tIFZuKzU0anFpaVVDRStXWmNFVlkz
        \\ZjFzcUhqbHUvejFMQ1EvVDdYbTdxSTAK7s9ix86RtDMnTmjU8vkTTLdMW/73vqpS
        \\yPC8DpksHoMx+2Y=
        \\-----END AGE ENCRYPTED FILE-----
    );
    var identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6".*;
    const test_file_key = "YELLOW SUBMARINE";

    const allocator = std.testing.allocator;
    var buffer: [ArmoredReader.MIN_BUFFER_SIZE]u8 = undefined;
    var reader: Reader = .init(allocator, &r, &buffer);

    var header = try reader.parse();
    defer header.deinit(allocator);

    try t.expectEqual(.v1, header.version.?);
    try t.expectEqual(1, header.recipients.items.len);
    try t.expectEqual(43, header.mac.?.len);

    try t.expectEqual(.X25519, header.recipients.items[0].type);
    try t.expectEqualStrings("TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc", header.recipients.items[0].args.?[0]);
    try t.expect(header.recipients.items[0].body != null);

    const id: Key = .{ .slice = .{ .k = &identity } };
    var file_key = try header.recipients.items[0].unwrap(allocator, id);
    defer file_key.deinit(allocator);

    try t.expect(header.recipients.items[0].state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key().bytes);
    try header.verify_hmac(&file_key);


    var identity_buf: [90]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", &identity);

    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try X25519.recoverPublicKey(x25519_secret_key);

    const key = try Key.init(allocator, public_key);
    defer key.deinit(allocator);
    try header.recipients.items[0].wrap(allocator, file_key, key);

    try t.expect(header.recipients.items[0].state == .wrapped);
}

test "iterator" {
    const t = std.testing;
    var r: Io.Reader = .fixed(
        \\age-encryption.org/v1
        \\-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
        \\EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U
        \\--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0
        \\
    );

    var header_buf: [Reader.Iterator.MAX_HEADER_SIZE]u8 = undefined;
    var header_writer: Io.Writer = .fixed(&header_buf);
    var iter: Reader.Iterator = .{ .r = &r, .header_writer = &header_writer };

    try t.expectEqualStrings("age-encryption.org/v1", (try iter.next()).bytes);
    try t.expectEqualStrings("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc", (try iter.next()).bytes);
    try t.expectEqualStrings("EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U", (try iter.next()).bytes);
    try t.expectEqualStrings("--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0", (try iter.next()).bytes);
    try t.expect((try iter.next()).bytes.len == 0);
}

test "invalid" {
    const t = std.testing;
    var r: Io.Reader = .fixed("age-encryption.org/v1\n-> \x7f\n");

    const allocator = std.testing.allocator;
    var reader: Reader = .init(allocator, &r, &.{});
    try t.expectError(error.InvalidAscii, reader.parse());
}

test "scrypt recipient" {
    const t = std.testing;
    var r: Io.Reader = .fixed(
        \\age-encryption.org/v1
        \\-> scrypt rF0/NwblUHHTpgQgRpe5CQ 10
        \\gUjEymFKMVXQEKdMMHL24oYexjE3TIC0O0zGSqJ2aUY
        \\--- IOXiQYStkoT1mvZW2tFOqZdhRVvj58egABx/sWfZQbc
        \\
    );
    const allocator = std.testing.allocator;
    var reader: Reader = .init(allocator, &r, &.{});

    var header = try reader.parse();
    defer header.deinit(allocator);

    try t.expectEqual(.v1, header.version.?);
    try t.expectEqual(1, header.recipients.items.len);
    try t.expectEqual(43, header.mac.?.len);

    try t.expectEqual(.scrypt, header.recipients.items[0].type);
    try t.expectEqualStrings("rF0/NwblUHHTpgQgRpe5CQ", header.recipients.items[0].args.?[0]);
    try t.expectEqualStrings("10", header.recipients.items[0].args.?[1]);
    try t.expectEqualStrings("gUjEymFKMVXQEKdMMHL24oYexjE3TIC0O0zGSqJ2aUY",header.recipients.items[0].body.?);
    try t.expectEqualStrings("IOXiQYStkoT1mvZW2tFOqZdhRVvj58egABx/sWfZQbc", header.mac.?);
}

test "ed25519 recipient" {
    const t = std.testing;
    var r: Io.Reader = .fixed(
        \\age-encryption.org/v1
        \\-> ssh-ed25519 xk+TSA xSh4cYHalYztTjXKULvJhGWIEp8gCSIQ/zx13jGzalw
        \\+Iil7T4RMV75FvQKvZD6gkjWsllUrW5SBHHxN2wMruw
        \\--- NXKZrxXl5+8EmJG1lcx01IeOzm1k7nmlEJbJ6Dbymlg
        \\
    );
    const allocator = std.testing.allocator;
    var reader: Reader = .init(allocator, &r, &.{});

    var header = try reader.parse();
    defer header.deinit(allocator);

    try t.expectEqual(.v1, header.version.?);
    try t.expectEqual(1, header.recipients.items.len);
    try t.expectEqual(43, header.mac.?.len);

    try t.expectEqual(.@"ssh-ed25519", header.recipients.items[0].type);
    try t.expectEqualStrings("xk+TSA", header.recipients.items[0].args.?[0]);
    try t.expectEqualStrings("xSh4cYHalYztTjXKULvJhGWIEp8gCSIQ/zx13jGzalw", header.recipients.items[0].args.?[1]);
    try t.expectEqualStrings("+Iil7T4RMV75FvQKvZD6gkjWsllUrW5SBHHxN2wMruw",header.recipients.items[0].body.?);
    try t.expectEqualStrings("NXKZrxXl5+8EmJG1lcx01IeOzm1k7nmlEJbJ6Dbymlg", header.mac.?);
}

test "rsa recipient" {
    const t = std.testing;
    var r: Io.Reader = .fixed(
        \\age-encryption.org/v1
        \\-> ssh-rsa UI4tAQ
        \\AmzFOlub++Nsaxhme3ynSwrSjYZwYIyt91m2+CXZnkOGDMurW8vVyERWQZRQxB5j
        \\c9KVBe+MhHGt8zMjhytnjepioA4bCJgnxLUKU4u8WzH68TbCFb5wcoiNkTVOejyy
        \\NGV+DSwX6vBCzxsaswpYFbhG0X6wzYweUqJgvovYW/k
        \\--- hwblgFvUGLpdna6xzrTwsfq3Y3ztKzeF7a0DaYwXnHA
        \\
    );
    const allocator = std.testing.allocator;
    var reader: Reader = .init(allocator, &r, &.{});

    var header = try reader.parse();
    defer header.deinit(allocator);

    try t.expectEqual(.v1, header.version.?);
    try t.expectEqual(1, header.recipients.items.len);
    try t.expectEqual(43, header.mac.?.len);

    try t.expectEqual(.@"ssh-rsa", header.recipients.items[0].type);
    try t.expectEqualStrings("UI4tAQ", header.recipients.items[0].args.?[0]);
    try t.expectEqualStrings(
            \\AmzFOlub++Nsaxhme3ynSwrSjYZwYIyt91m2+CXZnkOGDMurW8vVyERWQZRQxB5j
            \\c9KVBe+MhHGt8zMjhytnjepioA4bCJgnxLUKU4u8WzH68TbCFb5wcoiNkTVOejyy
            \\NGV+DSwX6vBCzxsaswpYFbhG0X6wzYweUqJgvovYW/k
            , header.recipients.items[0].body.?,
    );
    try t.expect(mem.eql(u8, header.mac.?, "hwblgFvUGLpdna6xzrTwsfq3Y3ztKzeF7a0DaYwXnHA"));
}
