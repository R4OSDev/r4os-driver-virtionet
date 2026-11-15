pub const flag_needs_checksum: u8 = 1 << 0;
pub const flag_data_valid: u8 = 1 << 1;
pub const known_flags: u8 = flag_needs_checksum | flag_data_valid;
pub const gso_none: u8 = 0;

pub const Action = enum(u8) {
    software,
    validated,
    complete_partial,
    reject_gso,
};

pub const Decision = struct {
    action: Action = .software,
    metadata_fallback: bool = false,
};

pub fn decide(flags: u8, gso_type: u8, checksum_capability_accepted: bool) Decision {
    if (gso_type != gso_none) return .{ .action = .reject_gso, .metadata_fallback = true };
    const unknown = (flags & ~known_flags) != 0;
    if ((flags & flag_needs_checksum) != 0) {
        return .{
            .action = .complete_partial,
            .metadata_fallback = unknown or (flags & flag_data_valid) != 0,
        };
    }
    if ((flags & flag_data_valid) != 0) {
        return if (!unknown and checksum_capability_accepted)
            .{ .action = .validated }
        else
            .{ .action = .software, .metadata_fallback = true };
    }
    return .{ .action = .software, .metadata_fallback = unknown };
}

/// Completes a virtio `NEEDS_CSUM` IPv4 TCP/UDP packet in place. The partial
/// checksum field already contains the pseudo-header seed; folding the L4
/// bytes including that seed produces the canonical checksum later verified
/// by the ordinary R4P software path.
pub fn completePartialChecksum(frame: []u8, checksum_start: u16, checksum_offset: u16) bool {
    const ethernet_bytes: usize = 14;
    if (frame.len < ethernet_bytes + 20) return false;
    if (readBe16(frame, 12) != 0x0800) return false;
    const ip = frame[ethernet_bytes..];
    if ((ip[0] >> 4) != 4) return false;
    const ip_header_bytes = @as(usize, ip[0] & 0x0f) * 4;
    if (ip_header_bytes < 20 or ip.len < ip_header_bytes) return false;
    const ip_total_bytes: usize = readBe16(ip, 2);
    if (ip_total_bytes < ip_header_bytes or ethernet_bytes + ip_total_bytes > frame.len) return false;
    if ((readBe16(ip, 6) & 0x3fff) != 0) return false;

    const expected_start = ethernet_bytes + ip_header_bytes;
    const expected_offset: usize = switch (ip[9]) {
        17 => 6,
        6 => 16,
        else => return false,
    };
    const start: usize = checksum_start;
    const offset: usize = checksum_offset;
    if (start != expected_start or offset != expected_offset) return false;
    const end = ethernet_bytes + ip_total_bytes;
    if (start >= end or start + offset + 2 > end) return false;
    if (ip[9] == 17 and end - start < 8) return false;
    if (ip[9] == 6) {
        if (end - start < 20) return false;
        const tcp_header_bytes = @as(usize, frame[start + 12] >> 4) * 4;
        if (tcp_header_bytes < 20 or tcp_header_bytes > end - start) return false;
    }

    var sum: u32 = 0;
    var cursor = start;
    while (cursor + 1 < end) : (cursor += 2) {
        sum += (@as(u32, frame[cursor]) << 8) | frame[cursor + 1];
    }
    if (cursor < end) sum += @as(u32, frame[cursor]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
    var completed: u16 = @intCast(~sum & 0xffff);
    if (ip[9] == 17 and completed == 0) completed = 0xffff;
    writeBe16(frame, start + offset, completed);
    return true;
}

/// The driver retains this header and frame when handoff returns Busy.
/// Mark software completion in that same header, so a retry cannot fold the
/// completed checksum again or promote an old DATA_VALID bit to a HW bypass.
/// No pending work also returns true; ordinary software verification remains
/// the receiver's responsibility. A rejected completion changes neither flags
/// nor frame bytes.
pub fn completePendingChecksum(frame: []u8, header_flags: *u8, checksum_start: u16, checksum_offset: u16) bool {
    if ((header_flags.* & flag_needs_checksum) == 0) return true;
    if (!completePartialChecksum(frame, checksum_start, checksum_offset)) return false;
    header_flags.* &= ~(flag_needs_checksum | flag_data_valid);
    return true;
}

fn readBe16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

fn writeBe16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @intCast(value >> 8);
    bytes[offset + 1] = @intCast(value & 0xff);
}

fn addWord(sum_in: u32, value: u16) u32 {
    return sum_in + value;
}

fn folded(sum_in: u32) u16 {
    var sum = sum_in;
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @intCast(sum);
}

test "DATA_VALID is used only after Netcore accepted the checksum capability" {
    const std = @import("std");
    try std.testing.expectEqual(Action.validated, decide(flag_data_valid, gso_none, true).action);
    const rejected = decide(flag_data_valid, gso_none, false);
    try std.testing.expectEqual(Action.software, rejected.action);
    try std.testing.expect(rejected.metadata_fallback);
    const unknown = decide(flag_data_valid | 0x80, gso_none, true);
    try std.testing.expectEqual(Action.software, unknown.action);
    try std.testing.expect(unknown.metadata_fallback);
    try std.testing.expectEqual(Action.reject_gso, decide(0, 1, true).action);
}

test "NEEDS_CSUM completion produces a software-verifiable UDP checksum" {
    const std = @import("std");
    var frame: [46]u8 = .{0} ** 46;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    writeBe16(&frame, 16, 32);
    frame[23] = 17;
    frame[26] = 192;
    frame[27] = 0;
    frame[28] = 2;
    frame[29] = 1;
    frame[30] = 192;
    frame[31] = 0;
    frame[32] = 2;
    frame[33] = 2;
    writeBe16(&frame, 34, 1234);
    writeBe16(&frame, 36, 4321);
    writeBe16(&frame, 38, 12);
    frame[42] = 'R';
    frame[43] = '4';
    frame[44] = 'O';
    frame[45] = 'S';

    var pseudo: u32 = 0;
    pseudo = addWord(pseudo, 0xc000);
    pseudo = addWord(pseudo, 0x0201);
    pseudo = addWord(pseudo, 0xc000);
    pseudo = addWord(pseudo, 0x0202);
    pseudo = addWord(pseudo, 17);
    pseudo = addWord(pseudo, 12);
    writeBe16(&frame, 40, folded(pseudo));

    try std.testing.expect(completePartialChecksum(&frame, 34, 6));

    var verify = pseudo;
    var cursor: usize = 34;
    while (cursor + 1 < frame.len) : (cursor += 2) {
        verify += (@as(u32, frame[cursor]) << 8) | frame[cursor + 1];
    }
    try std.testing.expectEqual(@as(u16, 0xffff), folded(verify));
}

test "partial checksum rejects mismatched offsets without changing bytes" {
    const std = @import("std");
    var frame: [42]u8 = .{0} ** 42;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    writeBe16(&frame, 16, 28);
    frame[23] = 17;
    const original = frame;
    try std.testing.expect(!completePartialChecksum(&frame, 34, 16));
    try std.testing.expectEqualSlices(u8, &original, &frame);
}

test "partial checksum rejects a TCP header beyond the packet without mutation" {
    const std = @import("std");
    var frame: [54]u8 = .{0} ** 54;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    writeBe16(&frame, 16, 40);
    frame[23] = 6;
    frame[46] = 0xf0;
    const original = frame;
    try std.testing.expect(!completePartialChecksum(&frame, 34, 16));
    try std.testing.expectEqualSlices(u8, &original, &frame);
}

fn busyUdpFixture() [46]u8 {
    var frame = [_]u8{0} ** 46;
    frame[12] = 8;
    frame[14] = 0x45;
    writeBe16(&frame, 16, 32);
    frame[23] = 17;
    @memcpy(frame[26..34], &[_]u8{ 192, 0, 2, 1, 192, 0, 2, 2 });
    writeBe16(&frame, 34, 1234);
    writeBe16(&frame, 36, 4321);
    writeBe16(&frame, 38, 12);
    writeBe16(&frame, 40, 0x8421);
    @memcpy(frame[42..46], "R4OS");
    return frame;
}

test "retained receive entry completes once across Busy then Ok without a HW promotion" {
    const std = @import("std");
    const Receiver = struct {
        calls: usize = 0,
        delivered: [46]u8 = undefined,
        const Result = enum { busy, ok };

        fn offer(self: *@This(), frame: *const [46]u8) Result {
            self.calls += 1;
            if (self.calls == 1) return .busy;
            self.delivered = frame.*;
            return .ok;
        }
    };
    for ([_]u8{ flag_needs_checksum, flag_needs_checksum | flag_data_valid, flag_needs_checksum | 0x80 }) |initial_flags| {
        var frame = busyUdpFixture();
        var flags = initial_flags;
        var receiver = Receiver{};
        var first: [46]u8 = undefined;
        var completions: usize = 0;
        for (0..2) |attempt| {
            const decision = decide(flags, gso_none, true);
            if (decision.action == .complete_partial) {
                try std.testing.expect(completePendingChecksum(&frame, &flags, 34, 6));
                completions += 1;
            }
            // Frozen checksum for this pseudo-header, UDP header and payload.
            try std.testing.expectEqual(@as(u16, 0xc497), readBe16(&frame, 40));
            const result = receiver.offer(&frame);
            if (attempt == 0) {
                try std.testing.expectEqual(Receiver.Result.busy, result);
                first = frame;
            } else {
                try std.testing.expectEqual(Receiver.Result.ok, result);
                try std.testing.expectEqual(Action.software, decision.action);
            }
        }
        try std.testing.expectEqual(@as(usize, 2), receiver.calls);
        try std.testing.expectEqual(@as(usize, 1), completions);
        try std.testing.expectEqualSlices(u8, &first, &receiver.delivered);
        try std.testing.expectEqual(initial_flags & ~(flag_needs_checksum | flag_data_valid), flags);
        var verify: u32 = 0x8421;
        var offset: usize = 34;
        while (offset < receiver.delivered.len) : (offset += 2) verify += readBe16(&receiver.delivered, offset);
        try std.testing.expectEqual(@as(u16, 0xffff), folded(verify));
    }
    var rejected = busyUdpFixture();
    const original = rejected;
    var flags: u8 = flag_needs_checksum | flag_data_valid;
    try std.testing.expect(!completePendingChecksum(&rejected, &flags, 34, 16));
    try std.testing.expectEqualSlices(u8, &original, &rejected);
    try std.testing.expectEqual(flag_needs_checksum | flag_data_valid, flags);
}
