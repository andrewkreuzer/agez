const std = @import("std");
const mem = std.mem;
const exit = std.posix.exit;
const ArrayList = std.ArrayList;
const File = std.fs.File;

const argz = @import("argz");
const String = argz.String;

const agez = @import("agez");
const age = agez.age;
const AgeIo = agez.AgeIo;
const Key = agez.Key;
const AgeEncryptor = agez.AgeEncryptor;
const AgeDecryptor = agez.AgeDecryptor;
const SshParser = agez.ssh.Parser;
const PemDecoder = agez.ssh.PemDecoder;
const Recipient = agez.Recipient;
const X25519 = agez.X25519;

const Args = struct {
    help: argz.Arg(bool) = .{ .description = "Prints the help text" },
    encrypt: argz.Arg(bool) = .{ .description = "Encrypt the input (default)" },
    decrypt: argz.Arg(bool) = .{ .description = "Decrypt the input" },
    output: argz.Arg(?String) = .{ .description = "Output to a path OUTPUT" },
    armor: argz.Arg(bool) = .{ .description = "Encrypt to a PEM encoded format" },
    passphrase: argz.Arg(bool) = .{ .description = "Encrypt with a passphrase" },
    recipient: argz.Arg(?ArrayList(String)) = .{ .description = "Encrypt to a specified RECIPIENT. Can be repeated" },
    recipients_file: argz.Arg(?ArrayList(String)) = .{ .short = "-R", .description = "Encrypt to recipients listed at PATH. Can be repeated" },
    identity: argz.Arg(?ArrayList(String)) = .{ .description = "Use the identity file at PATH. Can be repeated" },
    input: argz.Positional(?String) = .{ .description = "Input file, defaults to stdin" },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer if (gpa.deinit() == .leak) { std.debug.print("Leak detected\n", .{}); };
    defer arena.deinit();

    var cli = argz.Parse(Args).init(allocator);
    defer cli.deinit();
    const args = try cli.parse();

    const armored = args.armor;
    const decrypt = args.decrypt;
    const file_key: Key = try Key.init(allocator, 16);
    const options = AgeIo.Options {
        .read_buffer = try allocator.alloc(u8, 4096),
        .write_buffer = try allocator.alloc(u8, 4096),
    };
    const output = if (args.output) |o| o.inner else null;
    const input = if (args.input) |i| i.inner else null;
    var Io: AgeIo = try .init(input, output, options);
    defer {
        Io.deinit();
        allocator.free(options.read_buffer);
        allocator.free(options.write_buffer);
    }

    if (Io.output_tty and !decrypt and !armored) {
        std.debug.print(
            \\Output is a tty, it's not recommended to write arbitrary data to the terminal
            \\use -o, --output to specify a file or redirect stdout
            \\
            , .{});
        exit(1);
    }

    var recipients: ArrayList(Recipient) = .empty;
    if (args.recipient) |values| for (values.items) |recipient| {
        const r = try Recipient.fromAgePublicKey(allocator, recipient.inner, file_key);
        try recipients.append(allocator, r);
    };
    if (args.recipients_file) |files| for (files.items) |file_name| {
        var buf: [4096]u8 = undefined;

        const f: File = try AgeIo.openFile(file_name.inner);
        defer f.close();
        var file_buf: [4096]u8 = undefined;
        var reader = f.reader(&file_buf);
        const n = try reader.readStreaming(&buf);
        if (n == 0) continue;

        const prefix = buf[0..4];
        if (mem.eql(u8, prefix, "ssh-")) {
            const pk = try SshParser.parseOpenSshPublicKey(buf[0..n]);
            const r = try Recipient.fromSshPublicKey(allocator, pk, file_key);
            try recipients.append(allocator, r);
        } else if (mem.eql(u8, prefix, "age1")) {
            var fbs = std.io.fixedBufferStream(buf[0..n]);
            const r = fbs.reader();
            var line_buf: [90]u8 = undefined;
            var line_fbs = std.io.fixedBufferStream(&line_buf);
            const writer = line_fbs.writer();
            while (true) {
                r.streamUntilDelimiter(writer, '\n', line_buf.len) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                const line = line_fbs.getWritten();
                const recipient = try Recipient.fromAgePublicKey(allocator, line, file_key);
                try recipients.append(allocator, recipient);
                try line_fbs.seekTo(0);
            }
        } else {
            std.debug.print("Unrecognized recipient file format: {s}\n", .{file_name.inner});
        }
    };

    const identities: ?[]Key = switch (args.passphrase) {
        true => blk: {
            var id = try allocator.alloc(Key, 1);
            var passphrase_buf: [128]u8 = undefined;
            const passphrase = try AgeIo.read_passphrase(&passphrase_buf, !decrypt);
            defer std.crypto.secureZero(u8, passphrase);
            id[0] = try Key.init(allocator, passphrase);
            const r = try Recipient.fromPassphrase(allocator, passphrase, file_key);
            try recipients.append(allocator, r);
            break :blk id;
        },
        false => blk: {
            if (args.identity) |files| {
                var ids: ArrayList(Key) = .empty;
                for (files.items) |file_name| {
                    var identity_buf: [256]u8 = undefined;
                    defer std.crypto.secureZero(u8, &identity_buf);
                    const line = try AgeIo.readFirstLine(&identity_buf, file_name.inner);
                    const prefix = line[0..14];
                    if (line.len == 0) continue;
                    if (mem.eql(u8, prefix[0..PemDecoder.header.len], PemDecoder.header)) {
                        var in_buf: [PemDecoder.max_key_size]u8 = undefined;
                        const f = try AgeIo.openFile(file_name.inner);
                        defer f.close();
                        const n = try f.read(&in_buf);
                        const key = try SshParser.parseOpenSshPrivateKey(in_buf[0..n]);
                        try ids.append(allocator, key);
                        const r = try Recipient.fromSshKey(allocator, key, file_key);
                        try recipients.append(allocator, r);
                    } else if (
                        mem.eql(u8, prefix, X25519.BECH32_HRP_PRIVATE[0..14])
                    ) {
                        const key = try Key.init(allocator, line);
                        try ids.append(allocator, key);

                        const r = try Recipient.fromAgePrivateKey(allocator, line, file_key);
                        try recipients.append(allocator, r);
                    } else {
                        std.debug.print("Unrecognized identity file format: {s}\n", .{file_name.inner});
                        exit(1);
                    }
                }
                break :blk try ids.toOwnedSlice(allocator);
            } else break :blk null;
        }
    };
    defer {
        for (recipients.items) |*r| { r.deinit(allocator); }
        recipients.deinit(allocator);
        if (identities) |ids| {
            for (ids) |id| { id.deinit(allocator); }
            allocator.free(ids);
        }
    }

    if (recipients.items.len == 0) {
        std.debug.print("No recipients specified\n", .{});
        exit(1);
    }

    const reader = &Io.reader.interface;
    const writer = &Io.writer.interface;
    if (decrypt) {
        const decryptor: AgeDecryptor = .init(allocator, reader, writer);
        try decryptor.decrypt(identities.?);
    } else {
        const encryptor: AgeEncryptor = .init(allocator, reader, writer);
        try encryptor.encrypt(&file_key, recipients, armored);
    }
}
