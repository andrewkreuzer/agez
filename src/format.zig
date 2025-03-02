const std = @import("std");
const io = std.io;
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Allocator = mem.Allocator;
const AllocatorError = mem.Allocator.Error;
const ArrayList = std.ArrayList;

const armor = @import("armor.zig");
const ArmoredReader = armor.ArmoredReader;
const ArmoredWriter = armor.ArmoredWriter;
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

pub const Age = struct {
    version: ?V = null,
    recipients: ArrayList(Recipient),
    mac: ?[]u8 = null,
    header: ?[]u8 = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .recipients = ArrayList(Recipient).init(allocator),
        };
    }

    pub fn verify_hmac(self: *Self, allocator: Allocator, fk: *Key) bool {
        const encoded = generate_hmac(allocator, self.header.?, fk)
            catch return false;
        defer allocator.free(encoded);
        return std.mem.eql(u8, self.mac.?, encoded);
    }

    pub fn file_key(self: *Self, allocator: Allocator, identity: []const u8) !Key {
        for (self.recipients.items) |*r| {
            return r.unwrap(allocator, identity) catch |err| switch (err) {
                error.AuthenticationFailed => { continue; },
                else => return err,
            };
        }
        return error.AuthenticationFailed;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (self.recipients.items) |*r| {
            r.deinit(allocator);
        }
        self.recipients.deinit();
        if (self.mac) |mac| {
            allocator.free(mac);
        }
        if (self.header) |header| {
            allocator.free(header);
        }
        self.mac = null;
        self.header = null;
    }

};

/// The version of the age file.
const V = enum {
    v1,
    none,

    pub const prefix = "age-encryption.org/";

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

pub fn AgeReader(
    comptime ReaderType: type,
) type {
    return struct {
        const Self = @This();

        r: Reader,
        armored_reader: ArmoredReaderType = undefined,

        allocator: Allocator,

        const ArmoredReaderType = ArmoredReader(ReaderType);
        const Reader = union(enum) {
            armored: ArmoredReaderType.Reader,
            normal: ReaderType,

            pub fn read(self: *Reader) !usize {
                return switch (self) {
                    .armored => |armored| armored.read(),
                    .normal => |normal| normal.read(),
                    else => unreachable,
                };
            }

            pub fn readAll(self: Reader, buf: []u8) !usize {
                return switch (self) {
                    .armored => |armored| armored.readAll(buf),
                    .normal => |normal| normal.readAll(buf),
                };
            }

            pub fn readByte(self: Reader) !u8 {
                return switch (self) {
                    .armored => |armored| armored.readByte(),
                    .normal => |normal| normal.readByte(),
                };
            }

            pub fn streamUntilDelimiter(self: Reader, w: anytype, delim: u8, max_size: usize) !void {
                return switch (self) {
                    .armored => |armored| armored.streamUntilDelimiter(w, delim, max_size),
                    .normal => |normal| normal.streamUntilDelimiter(w, delim, max_size),
                };
            }
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

        pub fn Iterator() type {
            return struct {
                const Iter = @This();

                const MAX_HEADER_SIZE = 4096;
                const MAX_LINE_SIZE = 128;

                r: Reader,

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
                fn next(iter: *Iter, done: bool) ?Line {
                    if (done) return .{ .prefix =.end, .bytes = &[_]u8{} };

                    var fbs = io.fixedBufferStream(&iter.buf);
                    var r = iter.r;
                    const w = fbs.writer();
                    const max_size = iter.buf.len;

                    r.streamUntilDelimiter(w, '\n', max_size) catch |err| switch (err) {
                        error.EndOfStream => {
                            return .{ .prefix = .unknown, .bytes = fbs.getWritten(), };
                        },
                        else => unreachable,
                    };

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
                fn readUntilFalseOrEofIgnore(iter: *Iter, pred: fn (u8) bool, ignore: ?[]const u8) ![]u8 {
                    var fbs = io.fixedBufferStream(&iter.buf);
                    var r = iter.r;
                    var w = fbs.writer();
                    outer: while (true) {
                        const byte: u8 = try r.readByte();
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

        pub fn init(allocator: Allocator, reader: ReaderType) Self {
            return .{
                .allocator = allocator,
                .r = .{ .normal = reader },
            };
        }

        pub fn read(self: *Self) !Age {
            const Iter = Iterator();
            var iter: Iter = .{ .r = self.r };
            var age = Age.init(self.allocator);

            var done = false;
            while (iter.next(done)) |line| {
                switch (line.prefix) {
                    .armor_begin => {
                        self.armored_reader = ArmoredReaderType{ .r = self.r.normal };
                        const areader = self.armored_reader.reader();
                        self.r = .{ .armored = areader };
                        iter.r = self.r;

                    },
                    .version => age.version = V.fromStr(line.bytes),
                    .stanza => {
                        var args = blk: {
                            var a = std.ArrayList([]u8).init(self.allocator);
                            const stanza = line.bytes[3..];

                            var i: usize = 0;
                            var j: usize = 0;
                            while (j < stanza.len) {
                                if (!Self.isValidAscii(stanza[j])) {
                                    return error.InvalidAscii;
                                }
                                if (stanza[j] == ' ') {
                                    const value = try self.allocator.dupe(u8, stanza[i .. j]);
                                    try a.append(value);

                                    i = j + 1;
                                }
                                if (j == stanza.len - 1) {
                                    const value = try self.allocator.dupe(u8, stanza[i .. j + 1]);
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
                        );

                        const body = try self.allocator.alloc(u8, b.len);
                        @memcpy(body, b);

                        const recipient_type = args.swapRemove(0);
                        defer self.allocator.free(recipient_type);
                        try age.recipients.append(.{
                            .type = try RecipientType.fromString(recipient_type),
                            .args = try args.toOwnedSlice(),
                            .body = body,
                        });
                    },
                    .hmac => {
                        const start = Prefix.hmac_prefix.len + 1; // space
                        age.mac = try self.allocator.dupe(u8, line.bytes[start..]);
                        done = true; // ugh
                    },
                    .end => {
                        const header_len = iter.read - age.mac.?.len - 2; // space
                        age.header = try self.allocator.dupe(u8, iter.header[0..header_len]);
                        return age;
                    },
                    else => {
                        return error.Unexpected;
                    }
                }
            }
            return error.Unexpected;
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

        pub fn deinit(self: *Self) void {
            _ = self;
        }
    };
}

pub fn AgeWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();
        w: Writer,
        normal_writer: WriterType = undefined,
        armored_writer: ArmoredWriterType = undefined,
        armored: bool = false,

        allocator: Allocator,

        const ArmoredWriterType = ArmoredWriter(WriterType);
        const Writer = union(enum) {
            armored: ArmoredWriterType.Writer,
            normal: WriterType,

            pub fn write(self: Writer, buf: []const u8) !usize {
                return switch (self) {
                    .armored => |armored| armored.write(buf),
                    .normal => |normal| normal.write(buf),
                };
            }

            pub fn writeAll(self: Writer, buf: []const u8) !usize {
                return switch (self) {
                    .armored => |armored| armored.writeAll(buf),
                    .normal => |normal| normal.writeAll(buf),
                };
            }
        };

        pub fn init(allocator: Allocator, writer: WriterType, armored: bool) Self {
            var header_writer: Self = .{
                .allocator = allocator,
                .w = .{ .normal = writer },
                .normal_writer = writer,
                .armored = armored,
            };
            header_writer.writeArmorStartIfNeeded() catch unreachable;
            return header_writer;
        }

        pub fn write(self: *Self, fk: *const Key, age: Age) !void {
            var recip = std.ArrayList(u8).init(self.allocator);
            defer recip.deinit();
            var rwriter = recip.writer();
            for (age.recipients.items) |*r| {
                const rstring = try r.toString(self.allocator);
                _ = try rwriter.write(rstring);
                self.allocator.free(rstring);
            }

            const header = try std.fmt.allocPrint(
                self.allocator,
                \\{s}
                \\{s}
                \\---
            ,.{age.version.?.toString(),recip.items});
            defer self.allocator.free(header);

            const mac = try generate_hmac(
                self.allocator,
                header,
                fk,
            );

            try self.switchWriterIfNeeded();
            _ = try self.w.write(header);
            _ = try self.w.write(" ");
            _ = try self.w.write(mac);
            _ = try self.w.write("\n");
        }

        fn switchWriterIfNeeded(self: *Self) !void {
            if (!self.armored) return;
            switch (self.w) {
                .normal => {
                    self.armored_writer = ArmoredWriterType{ .w = self.normal_writer };
                    const awriter = self.armored_writer.writer();
                    self.w = .{ .armored = awriter };
                },
                .armored => {
                    self.w = .{ .normal = self.normal_writer };
                },
            }
        }

        fn writeArmorStartIfNeeded(self: *Self) !void {
            if (!self.armored) return;
            _ = try self.w.write(armor.armor_begin_marker);
            _ = try self.w.write("\n");
        }

        pub fn writeArmorEndIfNeeded(self: *Self) !void {
            if (!self.armored) return;
            try self.armored_writer.flush();
            _ = try self.w.write(armor.armor_end_marker);
            _ = try self.w.write("\n");
        }

        pub fn deinit(self: *Self) void {
            self.switchWriterIfNeeded() catch unreachable;
            self.writeArmorEndIfNeeded() catch unreachable;
        }
    };
}

pub fn generate_hmac(
    allocator: Allocator,
    header: []const u8,
    fk: *const Key
) AllocatorError![]u8 {
    const salt = [_]u8{};
    var buf_hmac_key = [_]u8{0} ** 32;
    var buf_header_hmac = [_]u8{0} ** 32;
    var buf_encode = [_]u8{0} ** 64;

    const k = hkdf.extract(&salt, fk.key());
    hkdf.expand(&buf_hmac_key, "header", k);
    hmac.create(&buf_header_hmac, header, &buf_hmac_key);

    const Encoder = std.base64.standard_no_pad.Encoder;
    const hmac_padded_len = Encoder.calcSize(buf_header_hmac.len);
    const encoded = Encoder.encode(buf_encode[0..hmac_padded_len], &buf_header_hmac);

    return allocator.dupe(u8, encoded);
}

test "age file" {
    const t = std.testing;
    const bech32 = @import("bech32.zig");
    const X25519 = std.crypto.dh.X25519;
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
    var age_reader = AgeReader(
        @TypeOf(fbs.reader()),
    ){
        .allocator = allocator,
        .r = .{ .normal = fbs.reader() },
    };
    defer age_reader.deinit();

    var age = try age_reader.read();
    defer age.deinit();

    try t.expect(age.version.? == .v1);
    try t.expect(age.recipients.items.len == 3);
    try t.expect(age.mac.?.len == 43);

    try t.expect(age.recipients.items[0].type == .X25519);
    try t.expect(age.recipients.items[0].args != null);
    try t.expect(age.recipients.items[0].body != null);

    var file_key = try age.recipients.items[0].unwrap(allocator, identity);
    defer file_key.deinit(allocator);

    try t.expect(age.recipients.items[0].state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key());
    try t.expect(age.verify_hmac(allocator, &file_key));


    var identity_buf: [90]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);

    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try X25519.recoverPublicKey(x25519_secret_key);

    try age.recipients.items[0].wrap(allocator, file_key, &public_key);

    try t.expect(age.recipients.items[0].state == .wrapped);
}

test "armored age file" {
    const t = std.testing;
    const bech32 = @import("bech32.zig");
    const X25519 = std.crypto.dh.X25519;
    var fbs = io.fixedBufferStream(
        \\-----BEGIN AGE ENCRYPTED FILE-----
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBURWlGMHlwcXIrYnB2Y3FY
        \\TnlDVkpwTDdPdXdQZFZ3UEw3S1FFYkZET0NjCkVtRUNBRWNLTituL1ZzOVNiV2lW
        \\K0h1MHIrRThSNzdEZFdZeWQ4M253N1UKLS0tIFZuKzU0anFpaVVDRStXWmNFVlkz
        \\ZjFzcUhqbHUvejFMQ1EvVDdYbTdxSTAK7s9ix86RtDMnTmjU8vkTTLdMW/73vqpS
        \\yPC8DpksHoMx+2Y=
        \\-----END AGE ENCRYPTED FILE-----
    );
    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    const test_file_key = "YELLOW SUBMARINE";

    const allocator = std.testing.allocator;
    var age_reader = AgeReader(
        @TypeOf(fbs.reader()),
    ){
        .allocator = allocator,
        .r = .{ .normal = fbs.reader() },
    };
    defer age_reader.deinit();

    var age = try age_reader.read();
    defer age.deinit();

    try t.expect(age.version.? == .v1);
    try t.expect(age.recipients.items.len == 1);
    try t.expect(age.mac.?.len == 43);

    try t.expect(age.recipients.items[0].type == .X25519);
    try t.expect(age.recipients.items[0].args != null);
    try t.expect(age.recipients.items[0].body != null);

    var file_key = try age.recipients.items[0].unwrap(allocator, identity);
    defer file_key.deinit(allocator);

    try t.expect(age.recipients.items[0].state == .unwrapped);

    try t.expectEqualSlices(u8, test_file_key, file_key.key());
    try t.expect(age.verify_hmac(allocator, &file_key));


    var identity_buf: [90]u8 = undefined;
    const Bech32 = try bech32.decode(&identity_buf, "AGE-SECRET-KEY-", identity);

    var x25519_secret_key: [32]u8 = undefined;
    _ = try bech32.convertBits(&x25519_secret_key, Bech32.data, 5, 8, false);
    const public_key: [32]u8 = try X25519.recoverPublicKey(x25519_secret_key);

    try age.recipients.items[0].wrap(allocator, file_key, &public_key);

    try t.expect(age.recipients.items[0].state == .wrapped);
}

test "iterator" {
    const t = std.testing;
    var fbs = io.fixedBufferStream(
        \\age-encryption.org/v1
        \\-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
        \\EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U
        \\--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0
    );

    var iter = AgeReader(
        @TypeOf(fbs.reader()),
    ).Iterator(){
        .r = .{ .normal = fbs.reader() },
    };

    try t.expectEqualStrings("age-encryption.org/v1", (iter.next(false)).?.bytes);
    try t.expectEqualStrings("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc", (iter.next(false)).?.bytes);
    try t.expectEqualStrings("EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U", (iter.next(false)).?.bytes);
    try t.expectEqualStrings("--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0", (iter.next(false)).?.bytes);
    try t.expect(iter.next(false).?.bytes.len == 0);
}

test "invalid" {
    const t = std.testing;
    var fbs = io.fixedBufferStream("age-encryption.org/v1\n-> \x7f\n");

    const allocator = std.testing.allocator;
    var age_reader = AgeReader(
        @TypeOf(fbs.reader()),
    ){
        .allocator = allocator,
        .r = . { .normal = fbs.reader() },
    };
    defer age_reader.deinit();
    try t.expectError(error.InvalidAscii, age_reader.read());
}
