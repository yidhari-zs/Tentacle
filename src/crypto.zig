const root = @import("root");
const zz = @import("zigzag");
const util = @import("util.zig");
const offsets = root.offsets;

const sdk_public_key = @embedFile("sdk_public_key.xml");
const server_public_key = @embedFile("server_public_key.xml");

pub fn init(allocator: zz.ChunkAllocator) void {
    const base = root.base;

    @as(*usize, @ptrFromInt(base + offsets.unwrapOffset(.CRYPTO_STR_1))).* = util.ptrToStringAnsi(sdk_public_key);

    var d: [39]u16 = @splat(0);
    for ([_]u16{ 27818, 40348, 47410, 27936, 51394, 33172, 51987, 8709, 44748, 23705, 45753, 21092, 57054, 52661, 369, 62630, 11725, 7496, 36921, 28271, 34880, 52645, 31515, 18214, 3108, 2077, 13490, 25459, 58590, 47504, 15163, 8951, 44748, 23705, 45753, 29284, 57054, 52661 }, 0..d.len - 1) |v, i| {
        const b: i16 = @bitCast(@as(u16, @truncate(@subWithOverflow(((i + ((i >> 31) >> 29)) & 0xF8), i).@"0")));
        d[i] = @byteSwap(v >> @as(u4, @intCast(@mod(-11 - b, 16))) | v << @as(u4, @intCast(@mod(b + 11, 16))));
    }

    @as(*usize, @ptrFromInt(base + offsets.unwrapOffset(.CRYPTO_STR_2))).* = util.ptrToStringAnsi(@ptrCast(&d));

    initializeRsaCryptoServiceProvider();

    _ = root.intercept(allocator, base + offsets.unwrapOffset(.NETWORK_STATE_CHANGE), NetworkStateHook);
}

const NetworkStateHook = struct {
    pub var originalFn: *const fn (usize, usize) callconv(.c) usize = undefined;

    pub fn callback(state: usize, a2: usize) callconv(.c) usize {
        if (state == 15) initializeRsaCryptoServiceProvider();
        return @This().originalFn(state, a2);
    }
};

pub fn initializeRsaCryptoServiceProvider() void {
    const base = root.base;

    const statics = @as(*usize, @ptrFromInt(base + offsets.unwrapOffset(.RSA_STATICS))).*;
    const rcsp_field: *usize = @ptrFromInt(statics + offsets.unwrapOffset(.RSA_STATIC_ID));

    const rsaCreate: *const fn () callconv(.c) usize = @ptrFromInt(base + offsets.unwrapOffset(.RSA_CREATE));
    const rsaFromXmlString: *const fn (usize, usize) callconv(.c) void = @ptrFromInt(base + offsets.unwrapOffset(.RSA_FROM_XML_STRING));

    const instance = rsaCreate();
    rsaFromXmlString(instance, util.ptrToStringAnsi(server_public_key));

    rcsp_field.* = instance;
}
