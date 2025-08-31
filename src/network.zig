const std = @import("std");
const zz = @import("zigzag");
const root = @import("root");
const util = @import("util.zig");
const unicode = std.unicode;

const cn_dispatch_prefix = unicode.utf8ToUtf16LeStringLiteral("https://globaldp-prod-cn01.juequling.com");
const global_dispatch_prefix = unicode.utf8ToUtf16LeStringLiteral("https://globaldp-prod-os01.zenlesszonezero.com");
const cn_sdk_domain = unicode.utf8ToUtf16LeStringLiteral("mihoyo.com");
const global_sdk_domain = unicode.utf8ToUtf16LeStringLiteral("hoyoverse.com");

const custom_dispatch_prefix = unicode.utf8ToUtf16LeStringLiteral("http://127.0.0.1:10100");
const custom_sdk_prefix = unicode.utf8ToUtf16LeStringLiteral("http://127.0.0.1:20100");

const ws2_32_name = unicode.utf8ToUtf16LeStringLiteral("Ws2_32.dll");

pub fn init(allocator: zz.ChunkAllocator) void {
    const ws2_32 = std.os.windows.kernel32.GetModuleHandleW(ws2_32_name).?;
    const getaddrinfo = std.os.windows.kernel32.GetProcAddress(ws2_32, "getaddrinfo").?;

    _ = root.intercept(allocator, @intFromPtr(getaddrinfo), GetaddrinfoHook);
    _ = root.intercept(allocator, root.base + root.offsets.unwrapOffset(.MAKE_INITIAL_URL), MakeInitialUrlHook);
    _ = root.intercept(allocator, root.base + root.offsets.unwrapOffset(.SYSTEM_URI_CREATE_THIS), SystemUriHook);
}

const MakeInitialUrlHook = struct {
    pub var originalFn: *const fn (usize, usize) callconv(.c) usize = undefined;

    pub fn callback(a1: usize, a2: usize) callconv(.c) usize {
        const str = util.readCSharpString(a1);

        if (std.mem.startsWith(u16, str, cn_dispatch_prefix)) {
            std.log.debug("dispatch request detected.", .{});
            util.csharpStringReplace(a1, cn_dispatch_prefix, custom_dispatch_prefix);
        } else if (std.mem.startsWith(u16, str, global_dispatch_prefix)) {
            std.log.debug("dispatch request detected.", .{});
            util.csharpStringReplace(a1, global_dispatch_prefix, custom_dispatch_prefix);
        } else if (std.mem.indexOf(u16, str, cn_sdk_domain)) |index| {
            std.log.debug("CN SDK request detected.", .{});
            util.csharpStringReplace(a1, str[0 .. index + cn_sdk_domain.len], custom_sdk_prefix);
        } else if (std.mem.indexOf(u16, str, global_sdk_domain)) |index| {
            std.log.debug("GLOBAL SDK request detected.", .{});
            util.csharpStringReplace(a1, str[0 .. index + global_sdk_domain.len], custom_sdk_prefix);
        }

        return @This().originalFn(a1, a2);
    }
};

const GetaddrinfoHook = struct {
    pub var originalFn: *const fn ([*:0]const u8, [*:0]const u8, usize, usize) callconv(.c) usize = undefined;
    const null_address: [:0]const u8 = "0.0.0.0";

    pub fn callback(node_name: [*:0]const u8, service_name: [*:0]const u8, hints: usize, result: usize) callconv(.c) usize {
        if (std.mem.eql(u8, std.mem.span(node_name), "globaldp-prod-cn01.juequling.com")) {
            std.log.debug("getaddrinfo: {s}, potential security file request", .{node_name});
            return @This().originalFn(null_address.ptr, service_name, hints, result);
        } else {
            return @This().originalFn(node_name, service_name, hints, result);
        }
    }
};

const SystemUriHook = struct {
    pub var originalFn: *const fn (usize, usize, u8, u32) callconv(.c) usize = undefined;
    const cn_asset_path_utf8 = "StandaloneWindows64/cn/";
    const oversea_asset_path_utf8 = "StandaloneWindows64/oversea/";
    const cn_asset_path_utf16 = unicode.utf8ToUtf16LeStringLiteral(cn_asset_path_utf8);

    pub fn callback(this: usize, url: usize, a2: u8, a3: u32) callconv(.c) usize {
        var temp: [2048]u8 = undefined;

        const str = util.readCSharpString(url);
        if (std.mem.indexOf(u16, str, cn_asset_path_utf16) != null) {
            const length = unicode.utf16LeToUtf8(&temp, str) catch return @This().originalFn(this, url, a2, a3);
            const path_index = std.mem.indexOf(u8, temp[0..length], cn_asset_path_utf8).?;

            const length_diff = oversea_asset_path_utf8.len - cn_asset_path_utf8.len;
            @memmove(temp[path_index + length_diff .. length + length_diff], temp[path_index..length]);
            @memcpy(temp[path_index .. path_index + oversea_asset_path_utf8.len], oversea_asset_path_utf8);
            temp[length + length_diff] = 0;

            std.log.debug("replaced: {s}", .{temp[0 .. length + length_diff]});
            return @This().originalFn(this, util.ptrToStringAnsi(temp[0 .. length + length_diff]), a2, a3);
        } else {
            return @This().originalFn(this, url, a2, a3);
        }
    }
};
