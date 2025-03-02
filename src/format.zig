const builtin = @import("builtin");
const std = @import("std");
const io = std.io;
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const PathType = std.fs.path.PathType;
const Reader = io.Reader;
const Allocator = std.mem.Allocator;
const AllocatorError = std.mem.Allocator.Error;

const armor = @import("armor.zig");
const ArmoredReader = armor.ArmoredReader;
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;
const RecipientType = Recipient.Type;

const FormatError = error{
    Unexpected,
    InvalidAscii,
    // InvalidHeader,
    // InvalidVersion,
    // UnsupportedVersion,
};

pub fn AgeFile(
    comptime ReaderType: type,
    comptime WriterType: type,
    comptime ArmoredReaderType: type,
    comptime ArmoredWriterType: type,
) type {
    return struct {
        const Self = @This();

        allocator: Allocator,

        r: ReaderType,
        w: WriterType,
        is_armored: bool = false,
        ar: ArmoredReaderType,
        aw: ArmoredWriterType,

        version: ?V = null,
        recipients: ?[]Recipient = null,
        mac: ?[]u8 = null,
        header: ?[]u8 = null,

        const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;

        const Prefix = union(enum) {
            const version_prefix = "age";
            const stanza_prefix = "-> ";
            const hmac_prefix = "---";

            armor_begin,
            version,
            stanza,
            hmac,
            end,
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

        /// The version of the age file.
        const V = enum {
            pub const prefix = "age-encryption.org/";

            v1,
            none,

            fn fromStr(str: []u8) V {
                if (mem.eql(u8, str, prefix ++ "v1")) {
                    return .v1;
                }
                return .none;
            }

            fn toString(self: V) []const u8 {
                switch (self) {
                    .v1 => return prefix ++ "v1",
                    .none => return "",
                }
            }

            fn eql(self: V, str: []u8) bool {
                return mem.eql(u8, str, @tagName(self));
            }
        };

        pub fn Iterator() type {
            return struct {
                const Iter = @This();

                const MAX_HEADER_SIZE = 4096;
                const MAX_LINE_SIZE = 128;

                r: ReaderType,
                ar: ArmoredReaderType,

                read: usize = 0,
                line: usize = 0,
                header: [MAX_HEADER_SIZE]u8 = [_]u8{0} ** MAX_HEADER_SIZE,

                buf: [MAX_LINE_SIZE]u8 = [_]u8{0} ** MAX_LINE_SIZE,

                const Line = struct {
                    prefix: Prefix = .unknown,
                    bytes: []u8,
                };

                /// Reads lines of the file,
                /// keeping track of the line number and header.
                fn next(iter: *Iter, armored: bool, done: bool) ?Line {
                    if (done) return .{ .prefix =.end, .bytes = &[_]u8{} };

                    var fbs = io.fixedBufferStream(&iter.buf);
                    var r = iter.r;
                    var ar = iter.ar;
                    const w = fbs.writer();
                    const max_size = iter.buf.len;

                    if (armored) {
                        ar.streamUntilDelimiter(w, '\n', max_size) catch |err| switch (err) {
                            error.EndOfStream => {
                                return .{ .prefix = .unknown, .bytes = fbs.getWritten(), };
                            },
                            else => unreachable,
                        };
                    } else {
                        r.streamUntilDelimiter(w, '\n', max_size) catch |err| switch (err) {
                            error.EndOfStream => {
                                return .{ .prefix = .unknown, .bytes = fbs.getWritten(), };
                            },
                            else => unreachable,
                        };
                    }

                    const line = fbs.getWritten();

                    if (armor.isArmorBegin(line)) {
                        return .{ .prefix = Prefix.armor_begin, .bytes = line, };
                    }

                    const start = iter.read;
                    const end = iter.read + line.len;

                    @memcpy(iter.header[start..end], line);

                    // add back the newline so our hmac is valid
                    iter.header[end] = '\n';
                    iter.read += 1;

                    iter.line += 1;
                    iter.read += line.len;

                    // TODO: fix index out of bounds
                    // when empty line
                    const prefix = line[0..3];
                    return .{
                        .prefix = Prefix.match(prefix),
                        .bytes = line,
                    };
                }

                /// Reads until the predicate returns false or EOF is reached.
                fn readUntilFalseOrEof(iter: *Iter, pred: fn (u8) bool) ![]u8 {
                    return iter.readUntilFalseOrEofIgnore(pred, null);
                }

                /// Reads until the predicate returns false or EOF is reached,
                /// ignoring the specified bytes.
                fn readUntilFalseOrEofIgnore(iter: *Iter, pred: fn (u8) bool, ignore: ?[]const u8, armored: bool) ![]u8 {
                    var fbs = io.fixedBufferStream(&iter.buf);
                    var r = iter.r;
                    var ar = iter.ar;
                    var w = fbs.writer();
                    outer: while (true) {
                        const byte: u8 = blk: {
                            if (armored) break :blk try ar.readByte()
                            else break :blk try r.readByte();
                        };
                        if (byte == '\n') { iter.line += 1; }

                        iter.header[iter.read] = byte;
                        iter.read += 1;

                        if (!pred(byte)) return fbs.getWritten();
                        if (ignore) |i| {
                            for (i) |c| {
                                if (byte == c) { continue :outer; }
                            }
                        }

                        try w.writeByte(byte);
                    }
                }
            };
        }

        pub fn read(self: *Self) !void {
            const Iter = Iterator();
            var iter: Iter = .{ .r = self.r, .ar = self.ar };
            var recipients = std.ArrayList(Recipient).init(self.allocator);
            var done = false;

            while (iter.next(self.is_armored, done)) |line| {
                switch (line.prefix) {
                    .armor_begin => {
                        self.is_armored = true;
                    },
                    .version => self.version = V.fromStr(line.bytes),
                    .stanza => {
                        var args = blk: {
                            var a = std.ArrayList([]u8).init(self.allocator);
                            const stanza = line.bytes[3..];

                            for (stanza) |c| {
                                if (!Self.isValidAscii(c)) {
                                    return error.InvalidAscii;
                                }
                            }

                            var i: usize = 0;
                            var j: usize = 0;
                            while (j < stanza.len) {
                                if (stanza[j] == ' ') {
                                    const value = try self.allocator.alloc(u8, j - i);
                                    @memcpy(value, stanza[i .. j]);
                                    try a.append(value);

                                    i = j + 1;
                                }
                                if (j == stanza.len - 1) {
                                    const value = try self.allocator.alloc(u8, j - i + 1);
                                    @memcpy(value, stanza[i .. j + 1]);
                                    try a.append(value);

                                    i = j + 1;
                                }
                                j += 1;
                            }

                            break :blk a;
                        };

                        const ignore = [_]u8{'\n'};
                        const b = try iter.readUntilFalseOrEofIgnore(
                            Self.isStanzaBody,
                            &ignore,
                            self.is_armored,
                        );

                        const body = try self.allocator.alloc(u8, b.len);
                        @memcpy(body, b);

                        const recipient_type = args.swapRemove(0);
                        defer self.allocator.free(recipient_type);
                        try recipients.append(.{
                            .type = try RecipientType.fromString(recipient_type),
                            .args = try args.toOwnedSlice(),
                            .body = body,
                        });
                    },
                    .hmac => {
                        const mac_len = line.bytes.len - 4; // prefix + space
                        const mac = try self.allocator.alloc(u8, mac_len);
                        @memcpy(mac, line.bytes[4..]);
                        self.mac = mac;
                        done = true; // ugh
                    },
                    .end => {
                        const header_len = iter.read - self.mac.?.len - 2; // space
                        self.header = try self.allocator.alloc(u8, header_len);
                        @memcpy(self.header.?[0..header_len], iter.header[0..header_len]);
                        self.recipients = try recipients.toOwnedSlice();
                        break;
                    },
                    else => {
                        return error.Unexpected;
                    }
                }
            }
        }

        pub fn write(self: *Self, fk: *const Key) !void {
            var recipients = std.ArrayList(u8).init(self.allocator);
            defer recipients.deinit();
            var rwriter = recipients.writer();
            for (self.recipients.?) |*r| {
                const rstring = try r.toString(self.allocator);
                _ = try rwriter.write(rstring);
                self.allocator.free(rstring);
            }

            const header = try std.fmt.allocPrint(
                self.allocator,
                \\{s}
                \\{s}
                \\---
            ,.{self.version.?.toString(),recipients.items});

            self.mac = try self.generate_hmac(
                self.allocator,
                header,
                fk,
            );

            if (self.is_armored) {
                _ = try self.aw.write(header);
                _ = try self.aw.write(" ");
                _ = try self.aw.write(self.mac.?);
                _ = try self.aw.write("\n");
            } else {
                _ = try self.w.write(header);
                _ = try self.w.write(" ");
                _ = try self.w.write(self.mac.?);
                _ = try self.w.write("\n");
            }
            self.allocator.free(header);
        }

        // The valid subset of ascii for age strings is 33-126
        // but we include 32 (space) for convenience
        fn isValidAscii(c: u8) bool {
            if (c < 32 or c > 126) {
                return false;
            }
            return true;
        }

        // TODO: validate wraps at 64 and trailing bits
        fn isStanzaBody(c: u8) bool {
            return c != '\n';
        }

        pub fn generate_hmac(
            self: *Self,
            allocator: Allocator,
            header: []const u8,
            fk: *const Key
        ) AllocatorError![]u8 {
            _ = self;
            const salt = [_]u8{};
            var buf_hmac_key = [_]u8{0} ** 32;
            var buf_header_hmac = [_]u8{0} ** 32;
            var buf_encode = [_]u8{0} ** 64;

            const k = hkdf.extract(&salt, fk.key());
            hkdf.expand(&buf_hmac_key, "header", k);
            hmac.create(&buf_header_hmac, header, &buf_hmac_key);

            const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);
            const hmac_padded_len = encoder.calcSize(buf_header_hmac.len);
            const encoded = encoder.encode(buf_encode[0..hmac_padded_len], &buf_header_hmac);

            return allocator.dupe(u8, encoded);
        }

        pub fn verify_hmac(self: *Self, fk: *Key) bool {
            const salt = [_]u8{};
            var buf_hmac_key = [_]u8{0} ** 32;
            var buf_header_hmac = [_]u8{0} ** 32;
            var buf_encode = [_]u8{0} ** 64;

            const k = hkdf.extract(&salt, fk.key());
            hkdf.expand(&buf_hmac_key, "header", k);
            hmac.create(&buf_header_hmac, self.header.?, &buf_hmac_key);

            const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);
            const hmac_padded_len = encoder.calcSize(self.mac.?.len);
            const encoded = encoder.encode(buf_encode[0..hmac_padded_len], &buf_header_hmac);

            return std.mem.eql(u8, self.mac.?, encoded);
        }

        pub fn file_key(self: *Self, identity: []const u8) !Key {
            for (self.recipients.?) |*r| {
                return r.unwrap(self.allocator, identity) catch |err| switch (err) {
                    error.AuthenticationFailed => { continue; },
                    else => return err,
                };
            }
            return error.AuthenticationFailed;
        }

        pub fn deinit(self: *Self) void {
            if (self.recipients) |recipients| {
                for (recipients) |*r| { r.deinit(self.allocator); }
                self.allocator.free(recipients);
            }
            if (self.mac) |mac| {
                self.allocator.free(mac);
            }
            if (self.header) |header| {
                self.allocator.free(header);
            }
            self.recipients = null;
            self.mac = null;
            self.header = null;
        }
    };
}

test "age file" {
    const t = std.testing;
    const bech32 = @import("bech32.zig");
    const X25519 = std.crypto.dh.X25519;
    const null_writer = std.io.null_writer;
    var fbs = io.fixedBufferStream(
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
    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    const test_file_key = "YELLOW SUBMARINE";

    const allocator = std.testing.allocator;
    var age_file = AgeFile(
        @TypeOf(fbs.reader()),
        @TypeOf(null_writer),
        @TypeOf(fbs.reader()),
        @TypeOf(null_writer),
    ){
        .allocator = allocator,
        .r = fbs.reader(),
        .w = null_writer,
        .ar = fbs.reader(),
        .aw = null_writer,
    };
    defer age_file.deinit();
    try age_file.read();

    try t.expect(age_file.version.? == .v1);
    try t.expect(age_file.recipients.?.len == 3);
    try t.expect(age_file.mac.?.len == 43);

    try t.expect(age_file.recipients.?[0].type == .X25519);
    try t.expect(age_file.recipients.?[0].args != null);
    try t.expect(age_file.recipients.?[0].body != null);

    var file_key = try age_file.recipients.?[0].unwrap(allocator, identity);
    defer file_key.deinit(allocator);

    try t.expect(age_file.recipients.?[0].state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key());
    try t.expect(age_file.verify_hmac(&file_key));


    var identity_buf: [90]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);

    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try X25519.recoverPublicKey(x25519_secret_key);

    try age_file.recipients.?[0].wrap(allocator, file_key, &public_key);

    try t.expect(age_file.recipients.?[0].state == .wrapped);
}

test "iterator" {
    const t = std.testing;
    const null_writer = std.io.null_writer;
    var fbs = io.fixedBufferStream(
        \\age-encryption.org/v1
        \\-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
        \\EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U
        \\--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0
    );

    var iter = AgeFile(
        @TypeOf(fbs.reader()),
        @TypeOf(null_writer),
        @TypeOf(fbs.reader()),
        @TypeOf(null_writer),
    ).Iterator(){
        .r = fbs.reader(),
        .ar = fbs.reader(),
    };

    try t.expectEqualStrings("age-encryption.org/v1", (iter.next(false, false)).?.bytes);
    try t.expectEqualStrings("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc", (iter.next(false, false)).?.bytes);
    try t.expectEqualStrings("EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U", (iter.next(false, false)).?.bytes);
    try t.expectEqualStrings("--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0", (iter.next(false, false)).?.bytes);
    try t.expect(iter.next(false, false).?.bytes.len == 0);
}

test "invalid" {
    const t = std.testing;
    const null_writer = std.io.null_writer;
    var fbs = io.fixedBufferStream("age-encryption.org/v1\n-> \x7f\n");

    const allocator = std.testing.allocator;
    var age_file = AgeFile(
        @TypeOf(fbs.reader()),
        @TypeOf(null_writer),
        @TypeOf(fbs.reader()),
        @TypeOf(null_writer),
    ){
        .allocator = allocator,
        .r = fbs.reader(),
        .w = null_writer,
        .ar = fbs.reader(),
        .aw = null_writer,
    };
    defer age_file.deinit();
    try t.expectError(error.InvalidAscii, age_file.read());
}
