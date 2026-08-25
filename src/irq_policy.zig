pub const queue_interrupt: u8 = 1 << 0;
pub const config_interrupt: u8 = 1 << 1;

/// Virtio's queue cause covers both TX and RX. A bounded used-index read is
/// therefore required before publishing RX work; configuration-only and
/// TX-only interrupts must not wake the RX protocol path.
pub fn hasRxWork(isr: u8, rx_last_used: u16, rx_used: u16) bool {
    return (isr & queue_interrupt) != 0 and rx_last_used != rx_used;
}

pub fn isConfigOnly(isr: u8) bool {
    return (isr & config_interrupt) != 0 and (isr & queue_interrupt) == 0;
}

test "Virtio TX-only queue and config causes do not schedule RX" {
    const std = @import("std");
    try std.testing.expect(!hasRxWork(queue_interrupt, 7, 7));
    try std.testing.expect(!hasRxWork(config_interrupt, 7, 8));
    try std.testing.expect(isConfigOnly(config_interrupt));
}

test "Virtio queue cause schedules RX only with a new used entry" {
    const std = @import("std");
    try std.testing.expect(hasRxWork(queue_interrupt, 7, 8));
    try std.testing.expect(hasRxWork(queue_interrupt | config_interrupt, 0xFFFF, 0));
}
