// VIRTNET.R4D - virtio-net Netzwerktreiber (moderner virtio-1.x-Transport).
//
// 0.56.36 (geplant als 0.56.24b): kompletter Neubau. Der Treiber spricht
// AUSSCHLIESSLICH den modernen PCI-Transport (Vendor-Capabilities +
// MMIO-Common-Config, VIRTIO_F_VERSION_1). Damit deckt er sowohl
// QEMU -device virtio-net-pci,disable-legacy=on (Device-ID 0x1041) als
// auch das transitionale Default-Device (0x1000, Capabilities vorhanden)
// ab. Reine Legacy-Geraete ohne moderne Capabilities (disable-modern=on)
// werden bewusst nicht unterstuetzt und sauber abgelehnt.
//
// R4D-Rahmen und IRQ-/Poll-Disziplin folgen RTL8139.R4D (drain-Guard,
// GSI-16-23-Mitregistrierung, Poll-Fallback per OPTION VIRTNET irq=off).

const r4os = @import("r4os");

comptime {
    asm (r4os.r4dev.driverEntriesAsm("virtnet_init", "virtnet_shutdown"));
}

const VENDOR_VIRTIO: u16 = 0x1AF4;
const DEVICE_NET_TRANSITIONAL: u16 = 0x1000;
const DEVICE_NET_MODERN: u16 = 0x1041;

// PCI-Capability-Walk
const PCI_REG_STATUS_COMMAND: u16 = 0x04;
const PCI_STATUS_CAP_LIST: u32 = 1 << 20; // Status-Bit 4 im oberen Word
const PCI_REG_CAP_PTR: u16 = 0x34;
const PCI_CAP_ID_VENDOR: u8 = 0x09;

// virtio_pci_cap.cfg_type
const CAP_COMMON: u8 = 1;
const CAP_NOTIFY: u8 = 2;
const CAP_ISR: u8 = 3;
const CAP_DEVICE: u8 = 4;

// Common-Config-Offsets (virtio 1.x, little-endian)
const COMMON_DEVICE_FEATURE_SELECT: u64 = 0x00;
const COMMON_DEVICE_FEATURE: u64 = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: u64 = 0x08;
const COMMON_DRIVER_FEATURE: u64 = 0x0C;
const COMMON_NUM_QUEUES: u64 = 0x12;
const COMMON_DEVICE_STATUS: u64 = 0x14;
const COMMON_QUEUE_SELECT: u64 = 0x16;
const COMMON_QUEUE_SIZE: u64 = 0x18;
const COMMON_QUEUE_ENABLE: u64 = 0x1C;
const COMMON_QUEUE_NOTIFY_OFF: u64 = 0x1E;
const COMMON_QUEUE_DESC: u64 = 0x20;
const COMMON_QUEUE_DRIVER: u64 = 0x28;
const COMMON_QUEUE_DEVICE: u64 = 0x30;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;

// Feature-Bits: Wort 0 traegt die Netz-Features, Wort 1 die Transport-
// Features (Bit 32 = VIRTIO_F_VERSION_1).
const FEATURE_W0_NET_MAC: u32 = 1 << 5;
const FEATURE_W0_NET_STATUS: u32 = 1 << 16;
const FEATURE_W1_VERSION_1: u32 = 1 << 0;
const NET_CONFIG_STATUS: u64 = 6;
const NET_STATUS_LINK_UP: u16 = 1;

const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

// virtio 1.x: Net-Header ist immer 12 Bytes (inkl. num_buffers), auch
// ohne MRG_RXBUF (Richtlinie NET_HDR_LEN=12 aus dem Roadmap-Eintrag).
const NET_HDR_LEN: usize = 12;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
// Ringgroessen (Zweierpotenzen, kleiner als das QEMU-Default 256, per
// queue_size-Write reduziert): 32 RX-Puffer reichen fuer die ~10-ms-
// Poll-Raster des net-rx-Tasks plus IRQ-Drain; 16 TX-Slots entsprechen
// dem RTL8139-Muster (4) mit Reserve fuer das TCP-Sende-Fenster.
const RX_RING: u16 = 32;
const TX_RING: u16 = 16;
const RX_BUF_SIZE: usize = 2048;
const TX_BUF_SIZE: usize = 2048;

// DMA-Layout (ein zusammenhaengender Bereich, Offsets 16-Byte-aligned):
const OFF_RX_DESC: usize = 0x0000; // 32*16 = 512
const OFF_RX_AVAIL: usize = 0x0200; // 4 + 32*2 + 2 = 70
const OFF_RX_USED: usize = 0x0400; // 4 + 32*8 + 2 = 262
const OFF_TX_DESC: usize = 0x0800; // 16*16 = 256
const OFF_TX_AVAIL: usize = 0x0A00;
const OFF_TX_USED: usize = 0x0C00;
const OFF_RX_BUF: usize = 0x1000; // 32*2048 = 64 KB
const OFF_TX_BUF: usize = 0x11000; // 16*2048 = 32 KB
const DMA_BYTES: u32 = 0x19000; // 100 KB

const RX_DRAIN_BUDGET: usize = 64;
const TX_RECLAIM_SPIN: usize = 400;

const State = struct {
    api: *const r4os.r4dev.DriverApi = undefined,
    active: bool = false,
    registered: bool = false,
    info: r4os.abi.PciDeviceInfo = .{},
    dma: r4os.abi.DmaBuffer = .{},
    adapter_index: i32 = -1,
    mac: [6]u8 = .{0} ** 6,
    link_status_feature: bool = false,

    // Gemappte BAR-Regionen (Index = BAR-Nummer)
    bars: [6]r4os.abi.MmioRegion = @splat(.{}),
    bar_mapped: [6]bool = .{false} ** 6,
    common_base: u64 = 0,
    isr_base: u64 = 0,
    device_base: u64 = 0,
    notify_base: u64 = 0,
    notify_multiplier: u32 = 0,
    rx_notify_addr: u64 = 0,
    tx_notify_addr: u64 = 0,

    // Ring-Zustand
    tx_lock: bool = false,
    rx_avail_idx: u16 = 0,
    rx_last_used: u16 = 0,
    tx_avail_idx: u16 = 0,
    tx_last_used: u16 = 0,
    tx_free_mask: u32 = (1 << TX_RING) - 1,

    // Zaehler / Diagnose
    rx_ok: u64 = 0,
    tx_ok: u64 = 0,
    rx_errors: u64 = 0,
    tx_errors: u64 = 0,
    bad_frames: u64 = 0,
    tx_busy: u64 = 0,
    poll_count: u64 = 0,
    poll_fallbacks: u64 = 0,
    notify_kicks: u64 = 0,
    last_isr: u16 = 0,

    // IRQ-Zustand (Muster RTL8139)
    irq_registered: bool = false,
    irq_register_result: i32 = 0,
    irq_routes: [10]u8 = .{0xFF} ** 10,
    irq_route_count: usize = 0,
    irq_active_route: u8 = 0xFF,
    irq_count: u64 = 0,
    irq_handled: u64 = 0,
    irq_unhandled: u64 = 0,
    irq_deferred: u64 = 0,
    irq_mode: u8 = 0,

    // Drain-Guard: IRQ darf einen laufenden Task-Drain nicht doppeln.
    drain_busy: bool = false,
    drain_pending: bool = false,
};

const VirtioCap = struct {
    cfg_type: u8 = 0,
    bar: u8 = 0,
    offset: u32 = 0,
    length: u32 = 0,
    notify_multiplier: u32 = 0,
    found: bool = false,
};

var state: State = .{};
var backend: r4os.abi.NetBackend = .{};
var poll_active: bool = false;

export fn virtnet_init(api: *const r4os.r4dev.DriverApi) callconv(.c) i32 {
    state = .{ .api = api };
    poll_active = false;
    var ctx = context();
    ctx.logInfo("VIRTNET.R4D init");

    const info = findDevice(&ctx) orelse {
        ctx.logWarn("VIRTNET.R4D device not found");
        return -1;
    };
    state.info = info;

    if (ctx.pciEnableBusMaster(info, r4os.abi.pci_enable_memory_space) != 0) {
        ctx.logError("VIRTNET.R4D bus master enable failed");
        return -2;
    }

    if (!discoverCaps(&ctx)) {
        // Kein moderner Transport: Legacy-only-Geraet, bewusst abgelehnt.
        ctx.logWarn("VIRTNET.R4D no modern virtio capabilities (legacy-only not supported)");
        return -3;
    }

    if (ctx.allocDmaRegion(DMA_BYTES, 4096, &state.dma) != 0 or state.dma.phys_addr == 0 or state.dma.virt_addr == 0) {
        ctx.logError("VIRTNET.R4D dma allocation failed");
        return -4;
    }

    if (!initDevice(&ctx)) {
        // initDevice loggt die konkrete Stufe; FAILED-Status setzen.
        mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, 0x80);
        ctx.freeDmaRegion(&state.dma);
        return -5;
    }
    state.active = true;

    backend = .{};
    backend.version = r4os.abi.net_backend_version;
    backend.size = @sizeOf(r4os.abi.NetBackend);
    backend.flags = r4os.abi.net_backend_flag_broadcast | r4os.abi.net_backend_flag_trusted;
    if (deviceCarrierUp(&state)) backend.flags |= r4os.abi.net_backend_flag_link_up;
    backend.mtu = 1500;
    backend.bus_kind = info.bus_kind;
    backend.bus = info.bus;
    backend.device = info.device;
    backend.function = info.function;
    backend.vendor_id = info.vendor_id;
    backend.device_id = info.device_id;
    backend.mac = state.mac;
    backend.context = &state;
    backend.transmit = transmit;
    backend.poll = poll;
    backend.shutdown = backendShutdown;
    backend.status = status;

    const adapter = ctx.registerNetBackend("virtnet", &backend);
    if (adapter < 0) {
        ctx.logError("VIRTNET.R4D register_net_backend failed");
        shutdownHardware(&ctx);
        return -6;
    }
    state.adapter_index = adapter;
    state.registered = true;
    setupInterrupt(&ctx);
    ctx.logInfo("VIRTNET.R4D registered");
    return 0;
}

export fn virtnet_shutdown() callconv(.c) i32 {
    var ctx = context();
    ctx.logInfo("VIRTNET.R4D shutdown");
    shutdownHardware(&ctx);
    return 0;
}

fn findDevice(ctx: *const r4os.r4dev.DriverContext) ?r4os.abi.PciDeviceInfo {
    var index: u32 = 0;
    const total = ctx.pciDeviceCount();
    while (index < total) : (index += 1) {
        var info: r4os.abi.PciDeviceInfo = .{};
        if (ctx.pciDeviceAt(index, &info) != 0) continue;
        if (info.vendor_id != VENDOR_VIRTIO) continue;
        if (info.device_id == DEVICE_NET_TRANSITIONAL or info.device_id == DEVICE_NET_MODERN) return info;
    }
    return null;
}

fn cfgByte(ctx: *const r4os.r4dev.DriverContext, offset: u16) u8 {
    const dword = ctx.pciReadConfig32(state.info, offset & 0xFFFC);
    const shift: u5 = @intCast((offset & 3) * 8);
    return @truncate(dword >> shift);
}

// Vendor-Capabilities (ID 0x09) einsammeln und die referenzierten BARs
// mappen. Liefert false, wenn kein Common-Config-Fenster existiert.
fn discoverCaps(ctx: *const r4os.r4dev.DriverContext) bool {
    const status_cmd = ctx.pciReadConfig32(state.info, PCI_REG_STATUS_COMMAND);
    if ((status_cmd & PCI_STATUS_CAP_LIST) == 0) return false;

    var caps: [4]VirtioCap = @splat(.{}); // Index = cfg_type - 1
    var bar_extent: [6]u32 = .{0} ** 6;

    var ptr: u16 = cfgByte(ctx, PCI_REG_CAP_PTR) & 0xFC;
    var guard: usize = 0;
    while (ptr != 0 and guard < 48) : (guard += 1) {
        const head = ctx.pciReadConfig32(state.info, ptr);
        const cap_id: u8 = @truncate(head);
        const next: u16 = @as(u16, @truncate(head >> 8)) & 0xFC;
        if (cap_id == PCI_CAP_ID_VENDOR) {
            const cfg_type: u8 = @truncate(head >> 24);
            const body = ctx.pciReadConfig32(state.info, ptr + 4);
            const bar: u8 = @truncate(body);
            const offset = ctx.pciReadConfig32(state.info, ptr + 8);
            const length = ctx.pciReadConfig32(state.info, ptr + 12);
            if (cfg_type >= CAP_COMMON and cfg_type <= CAP_DEVICE and bar < 6) {
                const slot = &caps[cfg_type - 1];
                if (!slot.found) {
                    slot.* = .{ .cfg_type = cfg_type, .bar = bar, .offset = offset, .length = length, .found = true };
                    if (cfg_type == CAP_NOTIFY) {
                        slot.notify_multiplier = ctx.pciReadConfig32(state.info, ptr + 16);
                    }
                    const extent = offset +| length;
                    if (extent > bar_extent[bar]) bar_extent[bar] = extent;
                }
            }
        }
        ptr = next;
    }

    if (!caps[CAP_COMMON - 1].found or !caps[CAP_NOTIFY - 1].found or !caps[CAP_ISR - 1].found or !caps[CAP_DEVICE - 1].found) {
        return false;
    }

    var bar: usize = 0;
    while (bar < 6) : (bar += 1) {
        if (bar_extent[bar] == 0) continue;
        if (ctx.pciMapBar(state.info, @intCast(bar), bar_extent[bar], 0, &state.bars[bar]) != 0 or state.bars[bar].virt_addr == 0) {
            ctx.logError("VIRTNET.R4D bar map failed");
            return false;
        }
        state.bar_mapped[bar] = true;
    }

    state.common_base = state.bars[caps[CAP_COMMON - 1].bar].virt_addr + caps[CAP_COMMON - 1].offset;
    state.isr_base = state.bars[caps[CAP_ISR - 1].bar].virt_addr + caps[CAP_ISR - 1].offset;
    state.device_base = state.bars[caps[CAP_DEVICE - 1].bar].virt_addr + caps[CAP_DEVICE - 1].offset;
    state.notify_base = state.bars[caps[CAP_NOTIFY - 1].bar].virt_addr + caps[CAP_NOTIFY - 1].offset;
    state.notify_multiplier = caps[CAP_NOTIFY - 1].notify_multiplier;
    return true;
}

// virtio-1.x-Initialisierung: Reset, Feature-Negotiation (VERSION_1 +
// MAC und optionaler Carrier-Status), Queue-Setup RX/TX, RX-Ring
// vorfuellen, DRIVER_OK.
fn initDevice(ctx: *const r4os.r4dev.DriverContext) bool {
    // Reset und warten, bis das Geraet 0 meldet.
    mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, 0);
    var spin: usize = 0;
    while (mmioRead8(state.common_base + COMMON_DEVICE_STATUS) != 0) : (spin += 1) {
        if (spin > 1000) {
            ctx.logError("VIRTNET.R4D reset timeout");
            return false;
        }
        ctx.waitTicks(1);
    }
    mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
    mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    mmioWrite32(state.common_base + COMMON_DEVICE_FEATURE_SELECT, 0);
    const feat0 = mmioRead32(state.common_base + COMMON_DEVICE_FEATURE);
    mmioWrite32(state.common_base + COMMON_DEVICE_FEATURE_SELECT, 1);
    const feat1 = mmioRead32(state.common_base + COMMON_DEVICE_FEATURE);
    if ((feat1 & FEATURE_W1_VERSION_1) == 0) {
        ctx.logError("VIRTNET.R4D device does not offer VERSION_1");
        return false;
    }
    if ((feat0 & FEATURE_W0_NET_MAC) == 0) {
        ctx.logError("VIRTNET.R4D device does not offer MAC feature");
        return false;
    }
    state.link_status_feature = (feat0 & FEATURE_W0_NET_STATUS) != 0;
    const driver_feat0 = FEATURE_W0_NET_MAC | if (state.link_status_feature) FEATURE_W0_NET_STATUS else 0;
    mmioWrite32(state.common_base + COMMON_DRIVER_FEATURE_SELECT, 0);
    mmioWrite32(state.common_base + COMMON_DRIVER_FEATURE, driver_feat0);
    mmioWrite32(state.common_base + COMMON_DRIVER_FEATURE_SELECT, 1);
    mmioWrite32(state.common_base + COMMON_DRIVER_FEATURE, FEATURE_W1_VERSION_1);

    mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if ((mmioRead8(state.common_base + COMMON_DEVICE_STATUS) & STATUS_FEATURES_OK) == 0) {
        ctx.logError("VIRTNET.R4D features rejected");
        return false;
    }

    const num_queues = mmioRead16(state.common_base + COMMON_NUM_QUEUES);
    if (num_queues < 2) {
        ctx.logError("VIRTNET.R4D too few queues");
        return false;
    }

    if (!setupQueue(ctx, RX_QUEUE, RX_RING, OFF_RX_DESC, OFF_RX_AVAIL, OFF_RX_USED, &state.rx_notify_addr)) return false;
    if (!setupQueue(ctx, TX_QUEUE, TX_RING, OFF_TX_DESC, OFF_TX_AVAIL, OFF_TX_USED, &state.tx_notify_addr)) return false;

    // MAC aus dem Device-Config-Fenster (nach FEATURES_OK gueltig).
    var i: usize = 0;
    while (i < 6) : (i += 1) state.mac[i] = mmioRead8(state.device_base + i);

    // RX-Ring komplett vorfuellen; avail.idx wird VOR DRIVER_OK
    // publiziert, der Kick folgt danach.
    var slot: u16 = 0;
    while (slot < RX_RING) : (slot += 1) {
        writeDesc(OFF_RX_DESC, slot, state.dma.phys_addr + OFF_RX_BUF + @as(u64, slot) * RX_BUF_SIZE, RX_BUF_SIZE, VIRTQ_DESC_F_WRITE);
        ramWrite16(OFF_RX_AVAIL + 4 + @as(usize, slot) * 2, slot);
    }
    compilerBarrier();
    ramWrite16(OFF_RX_AVAIL + 2, RX_RING);
    state.rx_avail_idx = RX_RING;

    mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    notifyQueue(&state, state.rx_notify_addr, RX_QUEUE);
    return true;
}

fn setupQueue(
    ctx: *const r4os.r4dev.DriverContext,
    queue: u16,
    ring_size: u16,
    off_desc: usize,
    off_avail: usize,
    off_used: usize,
    notify_addr: *u64,
) bool {
    mmioWrite16(state.common_base + COMMON_QUEUE_SELECT, queue);
    const device_size = mmioRead16(state.common_base + COMMON_QUEUE_SIZE);
    if (device_size == 0) {
        ctx.logError("VIRTNET.R4D queue missing");
        return false;
    }
    if (device_size > ring_size) {
        mmioWrite16(state.common_base + COMMON_QUEUE_SIZE, ring_size);
        if (mmioRead16(state.common_base + COMMON_QUEUE_SIZE) != ring_size) {
            ctx.logError("VIRTNET.R4D queue size not accepted");
            return false;
        }
    } else if (device_size < ring_size) {
        // Kleinere Device-Queues als unsere statischen Ringe sind nicht
        // vorgesehen (QEMU meldet 256).
        ctx.logError("VIRTNET.R4D queue smaller than driver ring");
        return false;
    }

    writeCommon64(COMMON_QUEUE_DESC, state.dma.phys_addr + off_desc);
    writeCommon64(COMMON_QUEUE_DRIVER, state.dma.phys_addr + off_avail);
    writeCommon64(COMMON_QUEUE_DEVICE, state.dma.phys_addr + off_used);

    const notify_off = mmioRead16(state.common_base + COMMON_QUEUE_NOTIFY_OFF);
    notify_addr.* = state.notify_base + @as(u64, notify_off) * state.notify_multiplier;

    mmioWrite16(state.common_base + COMMON_QUEUE_ENABLE, 1);
    return true;
}

fn transmit(raw_context: ?*anyopaque, frame: [*]const u8, len: u32) callconv(.c) i32 {
    const s = stateFrom(raw_context) orelse return 5;
    if (!s.active or s.dma.virt_addr == 0) return 5;
    if (len == 0 or len > TX_BUF_SIZE - NET_HDR_LEN) return 2;
    // 0.56.37: transmit() nicht reentrant (Slot-Bitmaske + avail-idx);
    // konkurrierende Sender (net-rx-Retransmit vs. Service-Task, siehe
    // RTL8139-Guard) bekommen busy(1) und pacen darauf.
    if (@atomicRmw(bool, &s.tx_lock, .Xchg, true, .acq_rel)) {
        s.tx_busy += 1;
        return 1;
    }
    defer @atomicStore(bool, &s.tx_lock, false, .release);

    reclaimTx(s);
    var slot = allocTxSlot(s);
    if (slot == null) {
        // Kurz nachfassen (QEMU raeumt TX praktisch synchron ab), sonst
        // busy an den Aufrufer - TCP paced per Retransmit.
        var spin: usize = 0;
        while (spin < TX_RECLAIM_SPIN and slot == null) : (spin += 1) {
            reclaimTx(s);
            slot = allocTxSlot(s);
        }
        if (slot == null) {
            s.tx_busy += 1;
            return 1;
        }
    }
    const slot_index = slot.?;

    const buf: [*]u8 = @ptrFromInt(s.dma.virt_addr + OFF_TX_BUF + @as(u64, slot_index) * TX_BUF_SIZE);
    var i: usize = 0;
    while (i < NET_HDR_LEN) : (i += 1) buf[i] = 0;
    i = 0;
    while (i < len) : (i += 1) buf[NET_HDR_LEN + i] = frame[i];

    writeDesc(OFF_TX_DESC, slot_index, s.dma.phys_addr + OFF_TX_BUF + @as(u64, slot_index) * TX_BUF_SIZE, @intCast(NET_HDR_LEN + len), 0);
    ramWrite16(OFF_TX_AVAIL + 4 + @as(usize, s.tx_avail_idx % TX_RING) * 2, slot_index);
    compilerBarrier();
    s.tx_avail_idx +%= 1;
    ramWrite16(OFF_TX_AVAIL + 2, s.tx_avail_idx);
    notifyQueue(s, s.tx_notify_addr, TX_QUEUE);
    return 0;
}

fn allocTxSlot(s: *State) ?u16 {
    var slot: u16 = 0;
    while (slot < TX_RING) : (slot += 1) {
        const bit = @as(u32, 1) << @intCast(slot);
        if ((s.tx_free_mask & bit) != 0) {
            s.tx_free_mask &= ~bit;
            return slot;
        }
    }
    return null;
}

fn reclaimTx(s: *State) void {
    const used_idx = ramRead16(OFF_TX_USED + 2);
    while (s.tx_last_used != used_idx) {
        const elem_off = OFF_TX_USED + 4 + @as(usize, s.tx_last_used % TX_RING) * 8;
        const id = ramRead32(elem_off);
        if (id < TX_RING) {
            s.tx_free_mask |= @as(u32, 1) << @intCast(id);
            s.tx_ok += 1;
        } else {
            s.tx_errors += 1;
        }
        s.tx_last_used +%= 1;
    }
}

fn poll(raw_context: ?*anyopaque) callconv(.c) void {
    const s = stateFrom(raw_context) orelse return;
    if (!s.active or s.dma.virt_addr == 0) return;
    if (poll_active) return;
    poll_active = true;
    defer poll_active = false;
    s.poll_count += 1;
    if (!s.irq_registered) {
        // Poll-Fallback: ISR lesen, damit eine anstehende INTx-Leitung
        // deassertiert wird (Read-to-clear), dann drainen.
        s.poll_fallbacks += 1;
        s.last_isr = mmioRead8(s.isr_base);
    }
    reclaimTx(s);
    s.drain_busy = true;
    drainRx(s);
    s.drain_busy = false;
    flushDeferredDrain(s);
}

fn drainRx(s: *State) void {
    var ctx = context();
    var processed: usize = 0;
    var reposted: usize = 0;
    while (processed < RX_DRAIN_BUDGET) : (processed += 1) {
        const used_idx = ramRead16(OFF_RX_USED + 2);
        if (s.rx_last_used == used_idx) break;
        const elem_off = OFF_RX_USED + 4 + @as(usize, s.rx_last_used % RX_RING) * 8;
        const id = ramRead32(elem_off);
        const total_len = ramRead32(elem_off + 4);
        s.rx_last_used +%= 1;
        if (id < RX_RING and total_len > NET_HDR_LEN) {
            const frame_len: usize = @min(@as(usize, total_len) - NET_HDR_LEN, RX_BUF_SIZE - NET_HDR_LEN);
            const data: [*]const u8 = @ptrFromInt(s.dma.virt_addr + OFF_RX_BUF + @as(u64, @intCast(id)) * RX_BUF_SIZE + NET_HDR_LEN);
            if (ctx.netReceiveFrame(s.adapter_index, data[0..frame_len]) == 0) {
                s.rx_ok += 1;
            } else {
                s.bad_frames += 1;
            }
        } else {
            s.rx_errors += 1;
        }
        if (id < RX_RING) {
            // Deskriptor unveraendert wiederverwenden und neu anbieten.
            ramWrite16(OFF_RX_AVAIL + 4 + @as(usize, s.rx_avail_idx % RX_RING) * 2, @intCast(id));
            s.rx_avail_idx +%= 1;
            reposted += 1;
        }
    }
    if (reposted > 0) {
        compilerBarrier();
        ramWrite16(OFF_RX_AVAIL + 2, s.rx_avail_idx);
        if ((ramRead16(OFF_RX_USED + 0) & VIRTQ_USED_F_NO_NOTIFY) == 0) {
            notifyQueue(s, s.rx_notify_addr, RX_QUEUE);
        }
    }
}

fn flushDeferredDrain(s: *State) void {
    while (s.drain_pending) {
        s.drain_pending = false;
        s.drain_busy = true;
        drainRx(s);
        s.drain_busy = false;
    }
}

fn backendShutdown(raw_context: ?*anyopaque) callconv(.c) i32 {
    _ = raw_context;
    var ctx = context();
    shutdownHardware(&ctx);
    return 0;
}

fn status(raw_context: ?*anyopaque, out: *r4os.abi.NetBackendStatus) callconv(.c) i32 {
    const s = stateFrom(raw_context) orelse return -1;
    out.* = .{
        .link_up = if (s.active and deviceCarrierUp(s)) 1 else 0,
        .rx_packets = s.rx_ok,
        .tx_packets = s.tx_ok,
        .drops = s.bad_frames,
        .errors = s.rx_errors + s.tx_errors,
        .irq_line = irqDisplayLine(s),
        .irq_pin = s.info.interrupt_pin,
        .irq_registered = if (s.irq_registered) 1 else 0,
        .irq_mode = s.irq_mode,
        .irq_count = s.irq_count,
        .irq_handled = s.irq_handled,
        .poll_count = s.poll_count,
        .poll_fallbacks = s.poll_fallbacks,
        .last_isr = s.last_isr,
        .reserved = @truncate(s.notify_kicks),
        .rx_errors = s.rx_errors,
        .tx_errors = s.tx_errors,
        .rx_overflows = 0,
        .rx_recoveries = 0,
    };
    return 0;
}

fn deviceCarrierUp(s: *const State) bool {
    // VIRTIO_NET_F_STATUS makes QEMU set bit 0 of virtio_net_config.status
    // for QMP set_link and real carrier changes. Older devices that do not
    // offer the feature retain the historical always-connected fallback.
    if (!s.link_status_feature) return true;
    return (mmioRead16(s.device_base + NET_CONFIG_STATUS) & NET_STATUS_LINK_UP) != 0;
}

fn setupInterrupt(ctx: *const r4os.r4dev.DriverContext) void {
    state.irq_mode = 0;
    state.irq_registered = false;
    state.irq_register_result = 0;
    state.irq_route_count = 0;
    state.irq_active_route = 0xFF;
    if (irqDisabled(ctx)) {
        state.irq_mode = 2;
        state.irq_register_result = -4;
        ctx.logWarn("VIRTNET.R4D irq disabled by option, polling fallback");
        return;
    }
    if (state.info.interrupt_pin == 0) {
        state.irq_mode = 2;
        state.irq_register_result = -1;
        ctx.logWarn("VIRTNET.R4D irq route missing, polling fallback");
        return;
    }
    if (state.info.interrupt_line != 0xFF) {
        _ = registerIrqRoute(ctx, state.info.interrupt_line);
    }
    // Q35 routet PCI-INTx auf GSI 16-23 (siehe RTL8139-0.56.21-Lehre);
    // der Handler prueft das ISR-Byte und meldet fremde IRQs unhandled.
    var gsi: u8 = 16;
    while (gsi < 24) : (gsi += 1) {
        _ = registerIrqRoute(ctx, gsi);
    }
    if (state.irq_route_count > 0) {
        state.irq_registered = true;
        state.irq_mode = 1;
        ctx.logInfo("VIRTNET.R4D irq registered");
    } else {
        state.irq_mode = 2;
        ctx.logWarn("VIRTNET.R4D irq register failed, polling fallback");
    }
}

fn registerIrqRoute(ctx: *const r4os.r4dev.DriverContext, route: u8) bool {
    if (route >= 32 or state.irq_route_count >= state.irq_routes.len) return false;
    var index: usize = 0;
    while (index < state.irq_route_count) : (index += 1) {
        if (state.irq_routes[index] == route) return true;
    }
    const result = ctx.irqRegister(route, irqHandler, @intFromPtr(&state), r4os.abi.irq_flag_shared | r4os.abi.irq_flag_level_low);
    state.irq_register_result = result;
    if (result != 0) return false;
    state.irq_routes[state.irq_route_count] = route;
    state.irq_route_count += 1;
    return true;
}

fn irqDisabled(ctx: *const r4os.r4dev.DriverContext) bool {
    const value = ctx.getOption("VIRTNET", "irq");
    return zEqIgnoreCase(value, "off") or zEqIgnoreCase(value, "disabled") or zEqIgnoreCase(value, "0");
}

fn irqHandler(irq: u8, raw_context: usize) callconv(.c) u32 {
    const s: *State = @ptrFromInt(raw_context);
    if (!s.active or s.dma.virt_addr == 0 or s.isr_base == 0) return 0;
    // ISR-Byte ist read-to-clear und deassertiert INTx.
    const isr = mmioRead8(s.isr_base);
    s.last_isr = isr;
    if (isr == 0) {
        s.irq_unhandled += 1;
        return 0;
    }
    s.irq_count += 1;
    s.irq_active_route = irq;
    if (s.drain_busy) {
        // Task-Kontext steht mitten im Drain: Nacharbeit anmelden statt
        // den Ring-Cursor parallel zu bewegen (RTL8139-0.56.21-Muster).
        s.irq_deferred += 1;
        s.drain_pending = true;
    } else {
        s.drain_busy = true;
        drainRx(s);
        s.drain_busy = false;
    }
    s.irq_handled += 1;
    return r4os.abi.irq_result_handled;
}

fn irqDisplayLine(s: *State) u8 {
    if (s.irq_active_route != 0xFF) return s.irq_active_route;
    if (s.irq_route_count > 0) return s.irq_routes[0];
    return s.info.interrupt_line;
}

fn shutdownHardware(ctx: *const r4os.r4dev.DriverContext) void {
    if (state.common_base != 0) {
        mmioWrite8(state.common_base + COMMON_DEVICE_STATUS, 0);
    }
    if (state.irq_registered) {
        var index: usize = 0;
        while (index < state.irq_route_count) : (index += 1) {
            _ = ctx.irqUnregister(state.irq_routes[index], irqHandler, @intFromPtr(&state));
        }
        state.irq_registered = false;
        state.irq_route_count = 0;
    }
    if (state.dma.phys_addr != 0) ctx.freeDmaRegion(&state.dma);
    state.active = false;
    state.registered = false;
}

fn notifyQueue(s: *State, addr: u64, queue: u16) void {
    if (addr == 0) return;
    @as(*volatile u16, @ptrFromInt(addr)).* = queue;
    s.notify_kicks += 1;
}

// --- Deskriptor-/Ring-Zugriffe (DMA-RAM, volatile gegen Reordering) ---

fn writeDesc(desc_base: usize, index: u16, addr: u64, len: u32, flags: u16) void {
    const off = desc_base + @as(usize, index) * 16;
    @as(*volatile u64, @ptrFromInt(state.dma.virt_addr + off)).* = addr;
    @as(*volatile u32, @ptrFromInt(state.dma.virt_addr + off + 8)).* = len;
    @as(*volatile u16, @ptrFromInt(state.dma.virt_addr + off + 12)).* = flags;
    @as(*volatile u16, @ptrFromInt(state.dma.virt_addr + off + 14)).* = 0;
}

fn ramRead16(off: usize) u16 {
    return @as(*volatile u16, @ptrFromInt(state.dma.virt_addr + off)).*;
}

fn ramRead32(off: usize) u32 {
    return @as(*volatile u32, @ptrFromInt(state.dma.virt_addr + off)).*;
}

fn ramWrite16(off: usize, value: u16) void {
    @as(*volatile u16, @ptrFromInt(state.dma.virt_addr + off)).* = value;
}

// --- MMIO-Zugriffe ---

fn mmioRead8(addr: u64) u8 {
    return @as(*volatile u8, @ptrFromInt(addr)).*;
}

fn mmioRead16(addr: u64) u16 {
    return @as(*volatile u16, @ptrFromInt(addr)).*;
}

fn mmioRead32(addr: u64) u32 {
    return @as(*volatile u32, @ptrFromInt(addr)).*;
}

fn mmioWrite8(addr: u64, value: u8) void {
    @as(*volatile u8, @ptrFromInt(addr)).* = value;
}

fn mmioWrite16(addr: u64, value: u16) void {
    @as(*volatile u16, @ptrFromInt(addr)).* = value;
}

fn mmioWrite32(addr: u64, value: u32) void {
    @as(*volatile u32, @ptrFromInt(addr)).* = value;
}

// 64-Bit-Common-Config-Felder als zwei 32-Bit-Writes (Spec-Vorgabe fuer
// Treiberzugriffe auf 64-Bit-Felder).
fn writeCommon64(offset: u64, value: u64) void {
    mmioWrite32(state.common_base + offset, @truncate(value));
    mmioWrite32(state.common_base + offset + 4, @truncate(value >> 32));
}

fn compilerBarrier() void {
    asm volatile ("" ::: .{ .memory = true });
}

fn stateFrom(raw_context: ?*anyopaque) ?*State {
    const ptr = raw_context orelse return null;
    return @ptrCast(@alignCast(ptr));
}

fn context() r4os.r4dev.DriverContext {
    return r4os.r4dev.DriverContext.init(state.api);
}

fn zEqIgnoreCase(value: [*:0]const u8, text: []const u8) bool {
    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        const c = value[index];
        if (c == 0 or upper(c) != upper(text[index])) return false;
    }
    return value[text.len] == 0;
}

fn upper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') return c - ('a' - 'A');
    return c;
}
