const std = @import("std");
const exit = std.posix.exit;

const lib = @import("lib");
const cli = lib.cli;
const bech32 = lib.bech32;
const Io = lib.Io;
const Key = lib.Key;
const Recipient = lib.Recipient;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer if (gpa.deinit() == .leak) { std.debug.print("Leak detected\n", .{}); };
    defer arena.deinit();

    const args = try cli.args(allocator);
    var io = try Io.init(args);
    defer io.deinit();

    const armored = args.armor.flag();
    const file_key: Key = try Key.initRandom(allocator, 16);

    var recipients = std.ArrayList(Recipient).init(allocator);
    if (args.recipient.values()) |values| for (values) |recipient| {
        var recipient_buf: [90]u8 = undefined;
        const decoded = try bech32.decode(&recipient_buf, lib.X25519.bech32_hrp_public, recipient);

        var public_key: [32]u8 = undefined;
        _ = try bech32.convertBits(&public_key, decoded.data, 5, 8, false);

        var r = Recipient{ .type = .X25519 };
        try r.wrap(allocator, file_key, &public_key);

        try recipients.append(r);
    };

    if (args.recipients_file.values()) |values| for (values) |recipient| {
        var recipient_file_buf = [_]u8{0} ** 90;
        defer std.crypto.utils.secureZero(u8, &recipient_file_buf);
        const recipient_file = try Io.recipient(&recipient_file_buf, recipient);

        var recipient_buf: [90]u8 = undefined;
        const decoded = try bech32.decode(&recipient_buf, "age", recipient_file);

        var public_key: [32]u8 = undefined;
        _ = try bech32.convertBits(&public_key, decoded.data, 5, 8, false);

        var r = Recipient{ .type = .X25519 };
        try r.wrap(allocator, file_key, &public_key);

        try recipients.append(r);
    };

    const identities: ?[]Key = switch (args.passphrase.flag()) {
        true => blk: {
            var ids = try allocator.alloc(Key, 1);
            var passphrase_buf = [_]u8{0} ** 128;
            const passphrase = try Io.read_passphrase(&passphrase_buf);
            defer std.crypto.utils.secureZero(u8, passphrase);
            ids[0] = try Key.init(allocator, passphrase);

            var r = Recipient{ .type = .scrypt };
            try r.wrap(allocator, file_key, passphrase);
            try recipients.append(r);

            break :blk ids;
        },
        false => blk: {
            if (args.identity.values()) |id_files| {
                for (id_files) |id_file| {
                    var ids = std.ArrayList(Key).init(allocator);
                    var identity_buf = [_]u8{0} ** 90;
                    defer std.crypto.utils.secureZero(u8, &identity_buf);
                    var recipient_buf: [90]u8 = undefined;
                    defer std.crypto.utils.secureZero(u8, &recipient_buf);
                    var secret_key: [32]u8 = undefined;
                    defer std.crypto.utils.secureZero(u8, &secret_key);

                    const id = try Io.identity(&identity_buf, id_file);
                    const key = try Key.init(allocator, id);
                    try ids.append(key);

                    var r = Recipient{ .type = .X25519 };
                    // const public_key = try key.public();

                    const decoded = try bech32.decode(&recipient_buf, lib.X25519.bech32_hrp_private, id);
                    _ = try bech32.convertBits(&secret_key, decoded.data, 5, 8, false);
                    var public_key = try std.crypto.dh.X25519.recoverPublicKey(secret_key);

                    try r.wrap(allocator, file_key, &public_key);
                    try recipients.append(r);

                    break :blk try ids.toOwnedSlice();
                }
            }
            break :blk null;
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

    if (args.decrypt.flag()) {
        try lib.decrypt(allocator, &io, identities.?);
    } else {
        try lib.encrypt(allocator, &io, file_key, recipients, armored);
    }
}
