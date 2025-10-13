const std = @import("std");
const exit = std.posix.exit;
const Io = std.Io;
const time = std.time;
const Allocator = std.mem.Allocator;
const ArgIterator = std.process.ArgIterator;
const ArrayList = std.ArrayList;
const File = std.fs.File;

const argz = @import("argz");
const String = argz.String;

const agez = @import("agez");
const X25519 = agez.X25519;
const bech32 = agez.bech32;

const Args2 = struct {
    help: argz.Arg(bool) = .{ .description = "Prints the help text" },
    output: argz.Arg(?String) = .{ .description = "Output private key to a path OUTPUT" },
    convert: argz.Arg(?String) = .{ .description = "Convert an identity file to a recipients file" },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer if (gpa.deinit() == .leak) { std.debug.print("Leak detected\n", .{}); };
    defer arena.deinit();

    var cli = argz.Parse(Args2).init(allocator);
    defer cli.deinit();

    const args = try cli.parse();
    if (args.convert) |convert| {
        var file = try std.fs.cwd().openFile(convert.inner, .{.mode = .read_write});
        var reader_buf: [4096]u8 = undefined;
        var reader: File.Reader = file.reader(&reader_buf);
        var writer_buf: [4096]u8 = undefined;
        var writer: File.Writer = file.writer(&writer_buf);

        var recipients: std.ArrayList([]u8) = .empty;
        defer {
            for (recipients.items) |r| allocator.free(r);
            recipients.deinit(allocator);
        }

        var buf_line: [90]u8 = undefined;
        var line_writer: Io.Writer = .fixed(&buf_line);
        while (true) {
            var buf_id: [90]u8 = undefined;
            var buf_bytes: [90]u8 = undefined;
            var buf_recipient: [90]u8 = undefined;
            var buf_recipient_b32: [90]u8 = undefined;

            _ = try reader.interface.streamDelimiter(&line_writer, '\n');
            const b32 = try bech32.decode(&buf_id, X25519.BECH32_HRP_PRIVATE, line_writer.buffered());
            _ = try bech32.convertBits(&buf_bytes, b32.data, 5, 8, false);

            const pk = try std.crypto.dh.X25519.recoverPublicKey(buf_bytes[0..32].*);
            const n = try bech32.convertBits(&buf_recipient, &pk, 8, 5, true);
            const recipient_bech32 = try bech32.encode(&buf_recipient_b32, "age", buf_recipient[0..n]);
            try recipients.append(allocator, try allocator.dupe(u8, recipient_bech32));
        }

        for (recipients.items) |r| {
            try writer.interface.writeAll(r);
            try writer.interface.writeByte('\n');
        }

        writer.interface.flush();
        file.close();
    } else {
        var secret: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &secret);

        var recipient_bech32_buf: [90]u8 = undefined;
        defer std.crypto.secureZero(u8, &recipient_bech32_buf);

        var identity_bech32_buf: [90]u8 = undefined;
        defer std.crypto.secureZero(u8, &identity_bech32_buf);

        std.crypto.random.bytes(&secret);

        const recipient = try std.crypto.dh.X25519.recoverPublicKey(secret);

        var buf3: [90]u8 = undefined;
        const n2 = try bech32.convertBits(&buf3, &secret, 8, 5, true);
        const identity_bech32 = try bech32.encode(&identity_bech32_buf, "AGE-SECRET-KEY-", buf3[0..n2]);

        var buf4: [90]u8 = undefined;
        const n3 = try bech32.convertBits(&buf4, &recipient, 8, 5, true);
        const recipient_bech32 = try bech32.encode(&recipient_bech32_buf, "age", buf4[0..n3]);

        var buf_upper: [90]u8 = undefined;
        const id = std.ascii.upperString(&buf_upper, identity_bech32);
        std.debug.print("Public key: {s}\n", .{recipient_bech32});
        if (args.output) |output| {
            var file = try std.fs.cwd().createFile(output.inner, .{.mode = 0o644});
            var writer_buf: [128]u8 = undefined;
            const file_writer = file.writer(&writer_buf);
            var writer: Io.Writer = file_writer.interface;
            try writer.writeAll("# created: ");
            try writer.writeAll(&try ts());
            try writer.writeAll("\n");
            try writer.writeAll("# public key: ");
            try writer.writeAll(recipient_bech32);
            try writer.writeAll("\n");
            try writer.writeAll(id);
            try writer.writeAll("\n");
            try writer.flush();
        } else {
            std.debug.print("{s}\n", .{id});
        }
    }

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

