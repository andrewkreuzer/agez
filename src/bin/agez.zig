const std = @import("std");
const mem = std.mem;
const exit = std.posix.exit;
const ArrayList = std.ArrayList;

const lib = @import("lib");
const cli = lib.cli;
const Io = lib.Io;
const Key = lib.Key;
const SshParser = lib.ssh.Parser;
const PemDecoder = lib.ssh.PemDecoder;
const Recipient = lib.Recipient;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer if (gpa.deinit() == .leak) { std.debug.print("Leak detected\n", .{}); };
    defer arena.deinit();

    const args = try cli.args(allocator);
    const armored = args.armor.flag();
    const decrypt = args.decrypt.flag();
    const file_key: Key = try Key.init(allocator, 16);
    var io = try Io.init(args.input.value(), args.output.value());
    defer io.deinit();

    if (io.output_tty and !decrypt and !armored) {
        std.debug.print(
            \\Output is a tty, it's not recommended to write arbitrary data to the terminal
            \\use -o, --output to specify a file or redirect stdout
            \\
            , .{});
        exit(1);
    }

    var recipients = ArrayList(Recipient).init(allocator);
    if (args.recipient.values()) |values| for (values) |recipient| {
        const r = try Recipient.fromAgePublicKey(allocator, recipient, file_key);
        try recipients.append(r);
    };
    if (args.recipients_file.values()) |files| for (files) |file_name| {
        const f = try Io.openFile(file_name);
        defer f.close();
        const reader = f.reader();
        var buf = [_]u8{0} ** 90;
        var fbs = std.io.fixedBufferStream(&buf);
        const writer = fbs.writer();
        while (true) {
            reader.streamUntilDelimiter(writer, '\n', buf.len) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            const line = fbs.getWritten();
            const recipient = try Recipient.fromAgePublicKey(allocator, line, file_key);
            try recipients.append(recipient);
            try fbs.seekTo(0);
        }
    };

    const identities: ?[]Key = switch (args.passphrase.flag()) {
        true => blk: {
            var id = try allocator.alloc(Key, 1);
            var passphrase_buf = [_]u8{0} ** 128;
            const passphrase = try Io.read_passphrase(&passphrase_buf);
            defer std.crypto.utils.secureZero(u8, passphrase);
            id[0] = try Key.init(allocator, passphrase);
            const r = try Recipient.fromPassphrase(allocator, passphrase, file_key);
            try recipients.append(r);
            break :blk id;
        },
        false => blk: {
            if (args.identity.values()) |files| {
                var ids = ArrayList(Key).init(allocator);
                for (files) |file_name| {
                    var identity_buf = [_]u8{0} ** 90;
                    defer std.crypto.utils.secureZero(u8, &identity_buf);

                    const line = try Io.readFirstLine(&identity_buf, file_name);
                    const prefix = line[0..14];
                    if (line.len == 0) continue;
                    if (mem.eql(u8, prefix[0..PemDecoder.header.len], PemDecoder.header)) {
                        var in_buf = [_]u8{0} ** PemDecoder.max_key_size;
                        const f = try Io.openFile(file_name);
                        const reader = f.reader();
                        const n = try reader.readAll(&in_buf);
                        const key = try SshParser.parseOpenSshPrivateKey(in_buf[0..n]);
                        try ids.append(key);
                        const r = try Recipient.fromSshKey(allocator, key, file_key);
                        try recipients.append(r);
                    } else {
                        const key = try Key.init(allocator, line);
                        try ids.append(key);

                        const r = try Recipient.fromAgePrivateKey(allocator, line, file_key);
                        try recipients.append(r);
                    }
                }
                break :blk try ids.toOwnedSlice();
            } else break :blk null;
        }
    };
    defer {
        for (recipients.items) |*r| { r.deinit(allocator); }
        recipients.deinit();
        if (identities) |ids| {
            for (ids) |id| { id.deinit(allocator); }
            allocator.free(ids);
        }
    }

    if (decrypt) {
        try lib.decrypt(allocator, &io, identities.?);
    } else {
        try lib.encrypt(allocator, &io, file_key, recipients, armored);
    }
}
