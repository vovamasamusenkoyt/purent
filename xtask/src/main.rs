use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn project_root() -> PathBuf {
    Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build() {
    let root = project_root();
    let esp_dir = root.join("target/esp");
    let boot_dir = esp_dir.join("EFI/BOOT");
    fs::create_dir_all(&boot_dir).expect("Failed to create ESP directory");

    println!("==> [PureNT xtask] 1. Building purent-kernel (x86_64-pc-windows-msvc) as purentoskrnl.exe...");
    let status = Command::new("cargo")
        .current_dir(&root)
        .env(
            "RUSTFLAGS",
            "-C linker=lld-link -C link-arg=/entry:KiSystemStartup -C link-arg=/subsystem:native -C link-arg=/base:0xFFFFF80000200000 -C link-arg=/nodefaultlib",
        )
        .args([
            "build",
            "--package",
            "purent-kernel",
            "--target",
            "x86_64-pc-windows-msvc",
        ])
        .status()
        .expect("Failed to build purent-kernel");
    assert!(status.success(), "purent-kernel build failed");

    let kernel_binary = root.join("target/x86_64-pc-windows-msvc/debug/purentoskrnl.exe");
    let dest_kernel = esp_dir.join("purentoskrnl.exe");
    fs::copy(&kernel_binary, &dest_kernel).expect("Failed to copy purentoskrnl.exe");

    println!("==> [PureNT xtask] 2. Building purent-boot (x86_64-unknown-uefi)...");
    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "--package",
            "purent-boot",
            "--target",
            "x86_64-unknown-uefi",
        ])
        .status()
        .expect("Failed to build purent-boot");
    assert!(status.success(), "purent-boot build failed");

    let uefi_binary = root.join("target/x86_64-unknown-uefi/debug/purent-boot.efi");
    let bootx64 = boot_dir.join("BOOTX64.EFI");
    fs::copy(&uefi_binary, &bootx64).expect("Failed to copy BOOTX64.EFI");

    println!("==> [PureNT xtask] ESP disk staged at {}", esp_dir.display());
}

fn run() {
    build();

    let root = project_root();
    let esp_dir = root.join("target/esp");
    let uefi_binary = esp_dir.join("EFI/BOOT/BOOTX64.EFI");
    let ovmf_path = "/usr/share/edk2/x64/OVMF.4m.fd";

    println!("==> [PureNT xtask] Starting QEMU with UEFI (OVMF)...");
    let status = Command::new("qemu-system-x86_64")
        .args([
            "-bios",
            ovmf_path,
            "-kernel",
            uefi_binary.to_str().unwrap(),
            "-drive",
            &format!("format=raw,file=fat:rw:{}", esp_dir.display()),
            "-serial",
            "stdio",
            "-m",
            "512M",
            "-display",
            "none",
        ])
        .status()
        .expect("Failed to execute QEMU");

    println!("==> [PureNT xtask] QEMU exited with {:?}", status);
}

fn main() {
    let arg = env::args().nth(1).unwrap_or_else(|| "build".into());
    match arg.as_str() {
        "build" => build(),
        "run" => run(),
        other => eprintln!("Unknown command: {}. Available: build, run", other),
    }
}
