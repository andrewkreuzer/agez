const std = @import("std");

const bech32 = @import("lib").bech32;

pub fn main() !void {

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

    std.debug.print("identity: {s}\n", .{identity_bech32});
    std.debug.print("recipient: {s}\n", .{recipient_bech32});
}
