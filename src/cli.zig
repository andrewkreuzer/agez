const builtin = @import("builtin");
const std = @import("std");
const exit = std.os.linux.exit;
const mem = std.mem;
const process = std.process;
const ArgIterator = process.ArgIterator;
const ArgIteratorGeneral = process.ArgIteratorGeneral;
const Allocator = std.mem.Allocator;

const Arg = struct {
    short: ?[]const u8 = null,
    long: ?[]const u8 = null,
    type: ?ArgType = null,
    description: ?[]const u8 = null,

    const ArgType = union(enum) {
        positional: []const u8,
        value: []const u8,
        multivalue: []const []const u8,
        flag: bool,
        none,
    };

    fn init(short: ?[]const u8, long: ?[]const u8, description: ?[]const u8) Arg {
        comptime {
            return .{
                .short = short,
                .long = long,
                .description = description,
            };
        }
    }

    fn set(self: *Arg, T: anytype) !void {
        switch(@TypeOf(T)) {
            bool => self.type = .{ .flag = T },
            [:0]const u8 => self.type = .{ .value = T },
            [][:0]const u8 => self.type = .{ .multivalue = T },
            else => {
                std.debug.print("Failed to set value: {any}\n", .{@TypeOf(T)});
                return error.FailedSettingValue;
            }
        }
    }

    pub fn flag(self: Arg) bool {
        if (self.type) |arg| switch (arg) {
            .flag => |b| return b,
            else => return false,
        } else return false;
    }

    pub fn value(self: Arg) ?[]const u8 {
        if (self.type) |arg| switch (arg) {
            .value, .positional => |v| return v,
            else => return null,
        } else return null;
    }

    pub fn values(self: Arg) ?[]const []const u8 {
        if (self.type) |arg| switch (arg) {
            .multivalue => |vs| return vs,
            else => return null,
        } else return null;
    }

    fn eql(self: Arg, arg: []const u8) bool {
        if (self.short == null or self.long == null) return false;
        return mem.eql(u8, arg, self.short.?) or mem.eql(u8, arg, self.long.?);
    }
};

const ArgError = error{
    InvalidArgument,
    EncryptAndDecrypt,
    IdRequiresEncryptDecrypt,
    FailedSettingValue,
};

pub fn args(allocator: Allocator) !Args {
    var iter = try ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();
    _ = iter.skip(); // skip the program name

    var a: Args =  .{ .allocator = allocator };
    a.parse(&iter) catch |err| switch (err) {
        error.InvalidArgument => exit(1),
        error.IdRequiresEncryptDecrypt => {
            std.debug.print("-i/--identity requires either -e/--encrypt or -d/--decrypt\n", .{});
            exit(1);
        },
        error.EncryptAndDecrypt => {
            std.debug.print("Incompatible arguments: --encrypt and --decrypt\n", .{});
            exit(1);
        },
        else => return err
    };
    return a;
}

pub const Args = struct {
    const Self = @This();

    help: Arg = Arg.init("-h", "--help", "Prints the help text"),
    encrypt: Arg = Arg.init("-e", "--encrypt", "Encrypt the input (default)"),
    decrypt: Arg = Arg.init("-d", "--decrypt", "Decrypt the input"),
    output: Arg = Arg.init("-o", "--output", "Output to a path OUTPUT"),
    armor: Arg = Arg.init("-a", "--armor", "Encrypt to a PEM encoded format"),
    passphrase: Arg = Arg.init("-p", "--passphrase", "Encrypt with a passphrase"),
    recipient: Arg = Arg.init("-r", "--recipient", "Encrypt to a specified RECIPIENT. Can be repeated"),
    recipients_file: Arg = Arg.init("-R", "--recipients-file", "Encrypt to recipients listed at PATH. Can be repeated"),
    identity: Arg = Arg.init("-i", "--identity", "Use the identity file at PATH. Can be repeated"),
    input: Arg = Arg.init(null, null, null),

    allocator: ?Allocator = null,

    pub fn parse(self: *Self, iter: anytype) anyerror!void {
        var empty = true;
        var recipients = std.ArrayList([:0]const u8).init(self.allocator.?);
        var recipients_file = std.ArrayList([:0]const u8).init(self.allocator.?);
        var identity = std.ArrayList([:0]const u8).init(self.allocator.?);
        while (iter.next()) |arg| {
            empty = false;
            if (self.help.eql(arg)) {
                try self.help.set(true);

            } else if (self.encrypt.eql(arg)) {
                if (self.decrypt.flag()) return error.EncryptAndDecrypt;
                try self.encrypt.set(true);

            } else if (self.decrypt.eql(arg)) {
                if (self.encrypt.flag()) return error.EncryptAndDecrypt;
                try self.decrypt.set(true);

            // TODO: don't assume next is okay to grab
            } else if (self.output.eql(arg)) {
                const output = iter.next() orelse return error.InvalidArgument;
                try self.output.set(output);

            } else if (self.armor.eql(arg)) {
                try self.armor.set(true);

            } else if (self.passphrase.eql(arg)) {
                try self.passphrase.set(true);

            } else if (self.recipient.eql(arg)) {
                const recipient = iter.next() orelse return error.InvalidArgument;
                try recipients.append(recipient);

            } else if (self.recipients_file.eql(arg)) {
                const recipient_file = iter.next() orelse return error.InvalidArgument;
                try recipients_file.append(recipient_file);

            } else if (self.identity.eql(arg)) {
                const id = iter.next() orelse return error.InvalidArgument;
                try identity.append(id);

            } else if (arg.len > 0) {
                self.input.type = .{ .positional = arg };

            } else {
                std.debug.print("Invalid argument {s}\n", .{arg});
                return error.InvalidArgument;
            }
        }

        try self.recipient.set(try recipients.toOwnedSlice());
        try self.recipients_file.set(try recipients_file.toOwnedSlice());
        try self.identity.set(try identity.toOwnedSlice());

        if (
            !self.encrypt.flag()
            and !self.decrypt.flag()
            and self.identity.type.?.multivalue.len > 0
        ) {
            return error.IdRequiresEncryptDecrypt;
        }

        if (empty or self.help.flag()) {
            try self.printHelp(self.allocator.?);
            exit(0);
        }
    }

    pub fn printHelp(_: *Self, allocator: Allocator) !void {
        const stdout = std.io.getStdOut().writer();

        const header =
            \\agez - age encryption
            \\
            \\ Usage:
            \\    agez [--encrypt] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]
            \\    agez [--encrypt] --passphrase [--armor] [-o OUTPUT] [INPUT]
            \\    agez --decrypt [-i PATH]... [-o OUTPUT] [INPUT]
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
                if (arg.short == null or arg.long == null) continue;
                const spacing = arg_spacing - arg.long.?.len + 2;
                try std.fmt.format(writer, "    {s}, {s}{s}{s}\n",
                    .{
                        arg.short.?,
                        arg.long.?,
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

    pub fn deinit(self: *Self) void {
        if (self.recipient.type) |recipient| {
            self.allocator.?.free(recipient.multivalue);
        }
        if (self.recipients_file.type) |recipients_file| {
            self.allocator.?.free(recipients_file.multivalue);
        }
        if (self.identity.type) |identity| {
            self.allocator.?.free(identity.multivalue);
        }
    }
};

test "arguments" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    const cases = [_]struct{
        args: []const u8,
        expected: Args,
    }{
        .{ .args = "--encrypt", .expected = .{
            .encrypt = .{ .type = .{ .flag = true, } },
        }},
        .{ .args = "--decrypt", .expected = .{
            .decrypt = .{ .type = .{ .flag = true, } },
        }},
        .{ .args = "--decrypt -i f", .expected = .{
            .decrypt = .{ .type = .{ .flag = true, } },
            .identity = .{ .type = .{ .value = "f", } },
        }},
    };

    for (cases) |c| {
        var iter = try std.process.ArgIteratorGeneral(.{}).init( allocator, c.args,);
        defer iter.deinit();

        var testing_args = Args{ .allocator = allocator };
        defer testing_args.deinit();

        try testing_args.parse(&iter);
        try t.expect(testing_args.encrypt.flag() == c.expected.encrypt.flag());
        try t.expect(testing_args.decrypt.flag() == c.expected.decrypt.flag());
        if (c.expected.output.value()) |v| {
            try t.expect(std.mem.eql(u8, testing_args.output.value().?, v));
        }
        try t.expect(testing_args.armor.flag() == c.expected.armor.flag());
        if (c.expected.passphrase.value()) |v| {
            try t.expect(std.mem.eql(u8, testing_args.passphrase.value().?, v));
        }
        if (c.expected.recipient.value()) |v| {
            try t.expect(std.mem.eql(u8, testing_args.recipient.value().?, v));
        }
        if (c.expected.recipients_file.value()) |v| {
            try t.expect(std.mem.eql(u8, testing_args.recipients_file.value().?, v));
        }
        if (c.expected.identity.value()) |e| if (testing_args.identity.value()) |g| {
            try t.expect(std.mem.eql(u8, e, g));
        };
    }
}

test "error" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    const cases = [_]struct{
        args: []const u8,
        expected: anyerror,
    }{
        .{ .args = "--encrypt -d", .expected = error.EncryptAndDecrypt },
    };

    for (cases) |c| {
        var iter = try std.process.ArgIteratorGeneral(.{}).init( allocator, c.args,);
        defer iter.deinit();

        var testing_args = Args{ .allocator = allocator };
        defer testing_args.deinit();

        try t.expectError(error.EncryptAndDecrypt, testing_args.parse(&iter));
    }
}
