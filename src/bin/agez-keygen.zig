const std = @import("std");
const exit = std.posix.exit;
const time = std.time;
const Allocator = std.mem.Allocator;
const ArgIterator = std.process.ArgIterator;

const agez = @import("agez");
const X25519 = agez.X25519;
const bech32 = agez.bech32;
const Arg = agez.cli.Arg;

const Args = struct {
    const Self = @This();

    help: Arg = Arg.init("-h", "-help", "print this help message"),
    output: Arg = Arg.init("-o", "-output", "output file for the private key"),
    convert: Arg = Arg.init("-y", "", "convert an identity file to a recipients file"),

    allocator: Allocator,

    pub fn parse(self: *Self, iter: anytype) anyerror!void {
        while (iter.next()) |arg| {
            if (self.help.eql(arg)) {
                try self.help.set(true);
            } else if (self.output.eql(arg)) {
                const out = iter.next() orelse return error.InvalidArgument;
                try self.output.set(out);
            } else if (self.convert.eql(arg)) {
                const convert = iter.next() orelse return error.InvalidArgument;
                try self.convert.set(convert);
            } else {
                std.debug.print("Invalid argument {s}\n", .{arg});
                return error.InvalidArgument;
            }
        }

        if (self.help.flag()) {
            try self.printHelp(self.allocator);
            exit(0);
        }
    }

    pub fn printHelp(_: *Self, allocator: Allocator) !void {
        const stdout = std.io.getStdOut().writer();

        const header =
            \\agez - age encryption
            \\
            \\ Usage:
            \\    age-keygen [-o OUTPUT]
            \\    age-keygen -y [-o OUTPUT] [INPUT]
            ;

        const arg_spacing = comptime blk: {
            var max: usize = 0;
            for (@typeInfo(Self).@"struct".fields) |field| {
                if (field.type != Arg)  continue;
                if (field.defaultValue()) |arg| {
                    if (arg.long == null) continue;
                    if (arg.long.?.len > max) max = arg.long.?.len;
                }
            }
            break :blk max;
        };

        // this is completely unnecessary, but I wanted to try it out
        const fields = @typeInfo(Self).@"struct".fields;
        var options = try std.ArrayList(u8).initCapacity(allocator, fields.len);
        const writer = options.writer();
        inline for (fields) |field| {
            if (field.type != Arg)  continue;
            if (field.defaultValue()) |arg| {
                if (arg.short == null) continue;
                const spacing = arg_spacing - arg.short.?.len + 2;
                try std.fmt.format(writer, "    {s}{s}{s}\n",
                    .{
                        arg.short.?,
                        " " ** spacing,
                        arg.description.?
                    }
                );
            }
        }

        const options_text = try options.toOwnedSlice();
        defer allocator.free(options_text);

        // TOOD: footer
        try std.fmt.format(stdout,
            \\{s}
            \\
            \\Options:
            \\{s}
            , .{header, options_text});
    }
};


fn args(allocator: Allocator) !Args {
    var iter = try ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();
    _ = iter.skip(); // skip the program name

    var a: Args =  .{ .allocator = allocator };
    a.parse(&iter) catch |err| switch (err) {
        error.InvalidArgument => exit(1),
        else => return err
    };
    return a;
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
    _ = try std.fmt.bufPrint(
        &buf,
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer if (gpa.deinit() == .leak) { std.debug.print("Leak detected\n", .{}); };
    defer arena.deinit();

    const _args = try args(allocator);
    if (_args.convert.value()) |convert| {
        var file = try std.fs.cwd().openFile(convert, .{.mode = .read_write});
        var buf_reader = std.io.bufferedReader(file.reader());
        var buf_writer = std.io.bufferedWriter(file.writer());
        const reader = buf_reader.reader();
        const writer = buf_writer.writer();

        var recipients = std.ArrayList([]u8).init(allocator);
        defer {
            for (recipients.items) |r| allocator.free(r);
            recipients.deinit();
        }

        var buf_line: [90]u8 = undefined;
        var line_fbs = std.io.fixedBufferStream(&buf_line);
        const line_writer = line_fbs.writer();
        while (true) {
            var buf_id: [90]u8 = undefined;
            var buf_bytes: [90]u8 = undefined;
            var buf_recipient: [90]u8 = undefined;
            var buf_recipient_b32: [90]u8 = undefined;

            try reader.streamUntilDelimiter(line_writer, '\n', buf_line.len);
            const b32 = try bech32.decode(&buf_id, X25519.BECH32_HRP_PRIVATE, line_fbs.getWritten());
            _ = try bech32.convertBits(&buf_bytes, b32.data, 5, 8, false);

            const pk = try std.crypto.dh.X25519.recoverPublicKey(buf_bytes[0..32].*);
            const n = try bech32.convertBits(&buf_recipient, &pk, 8, 5, true);
            const recipient_bech32 = try bech32.encode(&buf_recipient_b32, "age", buf_recipient[0..n]);
            try recipients.append(try allocator.dupe(u8, recipient_bech32));
        }

        for (recipients.items) |r| {
            try writer.writeAll(r);
            try writer.writeByte('\n');
        }

        buf_writer.flush();
        file.close();
    } else {
        var secret: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &secret);

        var recipient_bech32_buf: [90]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &recipient_bech32_buf);

        var identity_bech32_buf: [90]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &identity_bech32_buf);

        _ = std.os.linux.getrandom(
            &secret,
            secret.len,
            0x0002 // GRND_RANDOM
        );

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
        if (_args.output.value()) |output| {
            var file = try std.fs.cwd().createFile(output, .{.mode = 0o644});
            try file.writeAll("# created: ");
            try file.writeAll(&try ts());
            try file.writeAll("\n");
            try file.writeAll("# public key: ");
            try file.writeAll(recipient_bech32);
            try file.writeAll("\n");
            try file.writeAll(id);
            try file.writeAll("\n");
        } else {
            std.debug.print("{s}\n", .{id});
        }
    }

}
