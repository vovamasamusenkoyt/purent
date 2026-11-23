# PureNT

**PureNT** is a clean, native, modular NT-architecture operating system written from the ground up in Rust for AMD64 (`x86_64`).

Unlike translation layers that convert API calls to POSIX, PureNT implements native NT subsystem architecture: an Object Manager, an IRP-based I/O subsystem, and an in-kernel PE driver loader capable of executing binary `.sys` drivers directly.

---

## Current Status (Release 0.1)

- **Native UEFI Bootloader (`purent-boot`):** Self-contained, zero-dependency UEFI boot stage that configures canonical higher-half memory paging (PML4) and transitions to the kernel via `KiSystemStartup`.
- **PureNT Kernel (`purentoskrnl`):** 64-bit higher-half kernel running statically at `0xFFFFF80000200000` with custom GDT/TSS and active KPCR processor control block.
- **PE Driver Loader & Native Driver Execution:** Capable of loading authentic binary `.sys` kernel drivers directly from disk/memory, performing 64-bit base relocations (`IMAGE_REL_BASED_DIR64`), binding import address tables (IAT), and servicing `DriverEntry` initialization and IRP dispatch tables.
- **Subsystems Implemented:**
  - `purent-ntdef`: NT data structures (`KPCR`, `KPRCB`, `IRP`, `DRIVER_OBJECT`, `DEVICE_OBJECT`, `UNICODE_STRING`, `NTSTATUS`).
  - `purent-pe`: `#![no_std]` PE32+ parser and section mapper.
  - `purent-hal`: x86_64 hardware abstraction (GDT, 64-bit TSS, COM1 115200 baud UART).
  - `purent-boot`: UEFI loader application.
  - `purent-kernel`: Core executive and microkernel services (`Rtl`, `Io`, `Mm`, `Ke`).

---

## Workspace Layout

```
purent/
├── crates/
│   ├── purent-boot/       # UEFI bootloader (x86_64-unknown-uefi)
│   ├── purent-hal/        # x86_64 low-level hardware abstraction
│   ├── purent-kernel/     # purentoskrnl (x86_64-unknown-none)
│   ├── purent-ntdef/      # NT 64-bit architectural definitions
│   └── purent-pe/         # PE32+ parser and relocation engine
├── xtask/                 # PureNT build orchestrator and QEMU harness
├── LICENSE                # GNU GPLv2 (Kernel)
├── LICENSE-BSD            # BSD 3-Clause (Libraries & Bootloader)
└── Cargo.toml
```

---

## Quickstart

### Prerequisites

- Rust toolchain (`rustc`, `cargo`, `rustup`)
- `qemu-system-x86_64` and OVMF firmware (`/usr/share/edk2/x64/OVMF.4m.fd`)
- Target components:
  ```bash
  rustup target add x86_64-unknown-none
  rustup target add x86_64-unknown-uefi
  ```

### Building and Running

To build the bootloader, kernel, stage the FAT32 ESP partition, and launch in QEMU:

```bash
cargo run --package xtask -- run
```

Or just build the disk artifacts:

```bash
cargo run --package xtask -- build
```

---

## Licensing

PureNT uses a hybrid licensing model to balance community protection with open ecosystem adoption:

- **`crates/purent-kernel`** is licensed under the **GNU General Public License v2.0 (GPL-2.0-or-later)**.
- **`crates/purent-ntdef`**, **`crates/purent-pe`**, **`crates/purent-hal`**, **`crates/purent-boot`**, and **`xtask`** are licensed under the **BSD 3-Clause License**.
