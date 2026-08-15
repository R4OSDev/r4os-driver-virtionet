VIRTNET.R4D
===========

virtio-net-Netzwerktreiber fuer R4OS (0.56.36, geplant als 0.56.24b).

Transport
---------

Der Treiber spricht ausschliesslich den MODERNEN virtio-1.x-PCI-Transport:
Vendor-Capabilities (Common/Notify/ISR/Device-Config) + MMIO, Feature-
Negotiation mit VIRTIO_F_VERSION_1 und VIRTIO_NET_F_MAC. Damit werden
unterstuetzt:

  - QEMU -device virtio-net-pci,disable-legacy=on   (Device-ID 0x1041)
  - QEMU -device virtio-net-pci (transitional)       (Device-ID 0x1000,
    moderne Capabilities vorhanden)

Reine Legacy-Geraete (disable-modern=on, nur I/O-Port-Transport) werden
bewusst nicht unterstuetzt und mit Log-Warnung abgelehnt.

Aufbau
------

  - Split-Virtqueues RX=Q0 (32 Deskriptoren) / TX=Q1 (16 Slots) in einem
    zusammenhaengenden DMA-Bereich (100 KB inkl. 2-KB-Puffern).
  - Net-Header 12 Bytes (virtio 1.x, NET_HDR_LEN=12), kein MRG_RXBUF.
  - IRQ-first mit Poll-Fallback: INTx ueber interrupt_line + GSI 16-23
    (shared, level-low), ISR-Byte read-to-clear; Drain-Guard gegen
    parallelen IRQ-/Poll-Ring-Zugriff nach RTL8139-Muster.
  - OPTION VIRTNET irq=off erzwingt den Poll-Fallback.

Aktivierung
-----------

CONFIG.R4S:  DRIVER=VIRTNET

Build:

    cd Code\System\Driver\VirtioNet
    ..\..\..\..\DevTools\Zig\zig.exe build

Artefakt:

    zig-out\VIRTNET.R4D

Abnahme-Harness:

    Tests/Gate/Run-VirtioNetDhcpLiveTest05636.ps1
    (setzt ein zuvor gebautes Test-Image voraus; tauscht CONFIG.R4S/
    AUTOEXEC.BAT temporaer, faehrt QEMU mit
    -device virtio-net-pci,disable-legacy=on und prueft DHCP-Marker.)
