const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const exit = std.posix.exit;
const fs = std.fs;
const Io = std.Io;
const mem = std.mem;
const dh = crypto.dh;
const time = std.time;
const Allocator = std.mem.Allocator;
const File = std.fs.File;

const argz = @import("argz");
const String = argz.String;

const agez = @import("agez");
const X25519 = agez.X25519;
const bech32 = agez.bech32;

const Args = struct {
    input: argz.Positional(?String) = .{ .description = "Input private key from a path INPUT" },
    output: argz.Arg(?String) = .{ .description = "Output private key to a path OUTPUT" },
    convert: argz.Arg(bool) = .{ .short = "-y", .description = "Convert an identity file to a recipients file" },
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

    const stdin_file: File = .stdin();
    const stdout_file: File = .stdout();
    var in: File = if (args.input) |path|
        try fs.cwd().openFile(path.inner, .{}) else stdin_file;

    var out: File = if (args.output) |path|
        try fs.cwd().createFile(path.inner, .{.truncate = true, .mode = 0o600}) else stdout_file;


    var stdout_reader: File.Writer = stdout_file.writer(&.{});
    var stdout: *Io.Writer = &stdout_reader.interface;

    var in_reader_buf: [1024]u8 = undefined;
    var in_reader: File.Reader = in.reader(&in_reader_buf);
    var reader: *Io.Reader = &in_reader.interface;

    var out_writer_buf: [1024]u8 = undefined;
    var out_writer: File.Writer = out.writer(&out_writer_buf);
    var writer: *Io.Writer = &out_writer.interface;

    if (args.output != null and args.convert) {
        try stdout.print("Cannot use --output and --convert together\n", .{});
        exit(1);
    }

    if (args.output == null and !args.convert) {
        try cli.printHelp();
        exit(0);
    }

    if (args.convert) {
        while (reader.takeDelimiterExclusive('\n')) |line| {
            if (mem.startsWith(u8, line, "#")) continue;
            var n: usize = 0;
            var buf: [512]u8 = undefined;
            defer crypto.secureZero(u8, &buf);
            var w: Io.Writer = .fixed(&buf);

            const id_b32 = try bech32.decode(try w.writableSlice(90), X25519.BECH32_HRP_PRIVATE, line);
            const bits = try w.writableSlice(32);
            n = try bech32.convertBits(bits, id_b32.data, 5, 8, false);
            assert(n == 32);

            const pk = try dh.X25519.recoverPublicKey(bits[0..32].*);
            const bits_recipient = try w.writableSlice(90);
            n = try bech32.convertBits(bits_recipient, &pk, 8, 5, true);
            assert(n > 0);

            const recipient = try w.writableSlice(90);
            const recipient_b32 = try bech32.encode(recipient, "age", bits_recipient[0..n]);
            try writer.writeAll(recipient_b32);
            try writer.writeByte('\n');
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        }
    }

    if (args.output) |_| {
        var secret: [32]u8 = undefined;
        defer crypto.secureZero(u8, &secret);

        var recipient_bech32_buf: [90]u8 = undefined;
        defer crypto.secureZero(u8, &recipient_bech32_buf);

        var identity_bech32_buf: [90]u8 = undefined;
        defer crypto.secureZero(u8, &identity_bech32_buf);

        crypto.random.bytes(&secret);

        const recipient = try std.crypto.dh.X25519.recoverPublicKey(secret);

        var buf3: [90]u8 = undefined;
        const n2 = try bech32.convertBits(&buf3, &secret, 8, 5, true);
        const identity_bech32 = try bech32.encode(&identity_bech32_buf, "AGE-SECRET-KEY-", buf3[0..n2]);

        var buf4: [90]u8 = undefined;
        const n3 = try bech32.convertBits(&buf4, &recipient, 8, 5, true);
        const recipient_bech32 = try bech32.encode(&recipient_bech32_buf, "age", buf4[0..n3]);

        var buf_upper: [90]u8 = undefined;
        const id = std.ascii.upperString(&buf_upper, identity_bech32);
        try stdout.print("Public key: {s}\n", .{recipient_bech32});

        try writer.print(
            \\# created: {s}
            \\# public key: {s}
            \\{s}
            \\
            , .{ try ts(), recipient_bech32, id }
        );
    }

    try writer.flush();
    in.close();
    out.close();

}

fn ts() ![22]u8 {
    const timestamp = time.timestamp();

    const datetime = time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };

    const days = datetime.getEpochDay();
    const year_day = days.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const year = year_day.year;
    const month = month_day.month.numeric();
    const day = month_day.day_index;

    const day_secs = datetime.getDaySeconds();
    const seconds = day_secs.getSecondsIntoMinute();
    const minutes = day_secs.getMinutesIntoHour();
    const hour = day_secs.getHoursIntoDay();

    var buf: [22]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    _ = try writer.print(
        "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}UTC",
        .{
            year,
            month,
            day + 1,
            hour,
            minutes,
            seconds,
        }
    );
    return buf;
}

