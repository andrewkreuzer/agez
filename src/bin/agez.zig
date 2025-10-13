const std = @import("std");
const assert = std.debug.assert;
const exit = std.posix.exit;
const fs = std.fs;
const mem = std.mem;
const ArrayList = std.ArrayList;
const File = std.fs.File;
const Io = std.Io;

const argz = @import("argz");
const String = argz.String;

const agez = @import("agez");
const ssh = agez.ssh;
const pem = agez.ssh.pem;
const AgeIo = agez.AgeIo;
const IoOptions = AgeIo.Options;
const Key = agez.Key;
const AgeEncryptor = agez.AgeEncryptor;
const AgeDecryptor = agez.AgeDecryptor;
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

    const file_key: Key = try Key.init(allocator, 16);
    defer file_key.deinit(allocator);

    const armored = args.armor;
    const decrypt = args.decrypt;
    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    const options: IoOptions = .{
        .input = if (args.input) |i| i.inner else null,
        .output = if (args.output) |o| o.inner else null,
        .read_buffer = &read_buffer,
        .write_buffer = &write_buffer,
    };
    var age_io: AgeIo = try .init(options);
    defer age_io.deinit();
    binaryOutputWarning(age_io.output_tty and !decrypt and !armored);

    var recipients: ArrayList(Recipient) = .empty;
    if (args.recipient) |values| {
        for (values.items) |recipient| {
            const r: Recipient = try .fromAgePublicKey(
                allocator, recipient.inner, file_key
            );
            try recipients.append(allocator, r);
        }
    }

    if (args.recipients_file) |files| {
        for (files.items) |file_name| {
            const f: File = try fs.cwd().openFile(file_name.inner, .{});
            defer f.close();

            var buf: [1024]u8 = undefined;
            var reader = f.reader(&buf);
            const file = &reader.interface;

            const prefix = try file.peek(4);
            if (mem.eql(u8, prefix, "age1")) {

                while (file.takeDelimiterExclusive('\n')) |line| {
                    const recipient: Recipient = try .fromAgePublicKey(
                        allocator, line, file_key
                    );
                    try recipients.append(allocator, recipient);
                }else |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                }

            } else if (mem.eql(u8, prefix, "ssh-")) {

                var public_key: [1024]u8 = undefined;
                const n = try file.readSliceShort(&public_key);
                assert(n <= public_key.len);

                const contents = public_key[0..n];
                const pk = try ssh.Parser.parseOpenSshPublicKey(contents);
                const recipient: Recipient = try .fromSshPublicKey(
                    allocator, pk, file_key
                );
                try recipients.append(allocator, recipient);

            } else {
                std.debug.print(
                    "Unrecognized recipient file format: {s}\n",
                    .{file_name.inner}
                );
            }
        }
    }

    const identities: ?[]Key = switch (args.passphrase) {
        true => ids: {

            var passphrase_buf: [128]u8 = undefined;
            const passphrase = try AgeIo.read_passphrase(&passphrase_buf, !decrypt);
            defer std.crypto.secureZero(u8, passphrase);

            var ids = try allocator.alloc(Key, 1);
            ids[0] = try Key.init(allocator, passphrase);

            const recipient: Recipient = try.fromPassphrase(
                allocator, passphrase, file_key
            );
            try recipients.append(allocator, recipient);

            break :ids ids;
        },
        false => ids: {
            if (args.identity) |files| {
                var ids: ArrayList(Key) = .empty;
                for (files.items) |file_name| {
                    var identity_buf: [256]u8 = undefined;
                    defer std.crypto.secureZero(u8, &identity_buf);

                    const line = try AgeIo.readFirstLine(&identity_buf, file_name.inner);
                    if (line.len == 0) continue;

                    const prefix = line[0..14];
                    const bech_header = X25519.BECH32_HRP_PRIVATE[0..14];
                    if (mem.eql(u8, prefix[0..pem.prefix.len], pem.prefix)) {
                        var in_buf: [4096]u8 = undefined;
                        const f = try std.fs.cwd().openFile(file_name.inner, .{});
                        defer f.close();

                        const n = try f.read(&in_buf);
                        const key = try ssh.Parser.parseOpenSshPrivateKey(in_buf[0..n]);

                        try ids.append(allocator, key);
                        const r = try Recipient.fromSshKey(allocator, key, file_key);
                        try recipients.append(allocator, r);
                    } else if (mem.eql(u8, prefix, bech_header)) {
                        const key = try Key.init(allocator, line);
                        try ids.append(allocator, key);

                        const r = try Recipient.fromAgePrivateKey(allocator, line, file_key);
                        try recipients.append(allocator, r);
                    } else {
                        std.debug.print("Unrecognized identity file format: {s}\n", .{file_name.inner});
                        exit(1);
                    }
                }
                break :ids try ids.toOwnedSlice(allocator);
            } else break :ids null;
        }
    };
    defer {
        for (recipients.items) |*r| { r.deinit(allocator); }
        recipients.deinit(allocator);
        if (identities) |ids| {
            for (ids) |key| { key.deinit(allocator); }
            allocator.free(ids);
        }
    }

    if (recipients.items.len == 0) {
        std.debug.print("No recipients specified\n", .{});
        exit(1);
    }

    const reader = &age_io.reader.interface;
    const writer = &age_io.writer.interface;
    if (decrypt) {
        const decryptor: AgeDecryptor = .init(allocator, reader, writer);
        try decryptor.decrypt(identities.?);
    } else {
        const encryptor: AgeEncryptor = .init(allocator, reader, writer);
        try encryptor.encrypt(&file_key, recipients, armored);
    }
}

fn binaryOutputWarning(show: bool) void {
    if (show) {
        std.debug.print(
            \\Output is a tty, it's not recommended to write arbitrary data to the terminal
            \\use -o, --output to specify a file or redirect stdout
            \\
            , .{});
        exit(1);
    }
}
