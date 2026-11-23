use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod dwm;
use purent_ntdef::win32_modules::{BUILTIN_MODULES, LIBRARY_LOADER_API_SET};

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

    // Winver is optional and supplied by the local Windows reference image.
    for name in ["winver.exe", "winver.exe.mui"] {
        let source = root.join("refs/win7_7601_x64/winver").join(name);
        let destination = esp_dir.join(name);
        match fs::read(&source) {
            Ok(bytes) => fs::write(destination, bytes).expect("Failed to stage winver"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::write(destination, []).expect("Failed to stage empty winver resource");
            }
            Err(error) => panic!("Failed to read {}: {error}", source.display()),
        }
    }

    println!("==> [PureNT xtask] 1. Building User-Mode native subsystem (smss.exe)...");
    let status = Command::new("cargo")
        .current_dir(&root)
        .env(
            "RUSTFLAGS",
            "-C linker=lld-link -C link-arg=/entry:main -C link-arg=/subsystem:native -C link-arg=/base:0x0000000000400000 -C link-arg=/nodefaultlib",
        )
        .args([
            "build",
            "--package",
            "smss",
            "--target",
            "x86_64-pc-windows-msvc",
        ])
        .status()
        .expect("Failed to build smss");
    assert!(status.success(), "smss build failed");

    let smss_binary = root.join("target/x86_64-pc-windows-msvc/debug/smss.exe");
    let dest_smss = esp_dir.join("smss.exe");
    fs::copy(&smss_binary, &dest_smss).expect("Failed to copy smss.exe");

    for (package, executable, base, subsystem) in [
        ("conhost", "conhost.exe", "0x00500000", "native"),
        ("purent-dwm", "dwm.exe", "0x00600000", "native"),
        ("windowdemo", "windowdemo.exe", "0x140000000", "windows"),
    ] {
        let flags = format!(
            "-C linker=lld-link -C link-arg=/entry:main -C link-arg=/subsystem:{subsystem} -C link-arg=/base:{base} -C link-arg=/nodefaultlib"
        );
        let status = Command::new("cargo")
            .current_dir(&root)
            .env("RUSTFLAGS", flags)
            .args(["build", "--package", package, "--target", "x86_64-pc-windows-msvc"])
            .status()
            .expect("Failed to build desktop process");
        assert!(status.success(), "{package} build failed");
        fs::copy(root.join("target/x86_64-pc-windows-msvc/debug").join(executable), esp_dir.join(executable))
            .expect("Failed to stage desktop process");
    }

    println!("==> [PureNT xtask] 2. Building Win32 modules...");
    for &(file, base) in BUILTIN_MODULES {
        let name = file.strip_suffix(".dll").unwrap();
        let mut flags = format!(
            "-C linker=lld-link -C link-arg=/entry:DllMain -C link-arg=/subsystem:native -C link-arg=/nodefaultlib -C link-arg=/base:{base:#x}"
        );
        if name == "kernel32" {
            for symbol in ["RtlCaptureContext", "RtlLookupFunctionEntry", "RtlVirtualUnwind"] {
                flags.push_str(&format!(" -C link-arg=/export:{symbol}=ntdll.{symbol}"));
            }
            let contract = LIBRARY_LOADER_API_SET.strip_suffix(".dll").unwrap();
            for symbol in ["GetModuleHandleW", "GetProcAddress"] {
                flags.push_str(&format!(" -C link-arg=/export:{symbol}={contract}.{symbol}"));
            }
        }
        let status = Command::new("cargo")
            .current_dir(&root)
            .env("RUSTFLAGS", flags)
            .args(["build", "--package", &format!("purent-{name}"), "--target", "x86_64-pc-windows-msvc"])
            .status()
            .expect("Failed to build Win32 module");
        assert!(status.success(), "{file} build failed");
        fs::copy(root.join("target/x86_64-pc-windows-msvc/debug").join(file), esp_dir.join(file))
            .expect("Failed to stage Win32 module");
    }

    match fs::remove_file(esp_dir.join("purent_win32.dll")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("Failed to remove obsolete staged runtime: {error}"),
    }

    let cmd_binary = root.join("refs/win7_7601_x64/binaries/cmd.exe");
    let dest_cmd = esp_dir.join("cmd.exe");
    if cmd_binary.exists() {
        fs::copy(&cmd_binary, &dest_cmd).expect("Failed to copy cmd.exe");
    }

    println!("==> [PureNT xtask] 3. Building purent-kernel (x86_64-pc-windows-msvc) as purentoskrnl.exe...");
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

    println!("==> [PureNT xtask] 4. Building purent-boot (x86_64-unknown-uefi)...");
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

    println!("==> [PureNT xtask] Starting QEMU with UEFI (OVMF) in 1280x720...");
    let status = Command::new("qemu-system-x86_64")
        .args([
            "-bios",
            ovmf_path,
            "-kernel",
            uefi_binary.to_str().unwrap(),
            "-drive",
            &format!("format=raw,file=fat:rw:{}", esp_dir.display()),
            "-device",
            "VGA,edid=on,xres=1280,yres=720",
            "-serial",
            "stdio",
            "-m",
            "512M",
            "-display",
            "gtk",
        ])
        .status()
        .expect("Failed to execute QEMU");

    println!("==> [PureNT xtask] QEMU exited with {:?}", status);
}

fn screenshot() {
    build();

    let root = project_root();
    let esp_dir = root.join("target/esp");
    let uefi_binary = esp_dir.join("EFI/BOOT/BOOTX64.EFI");
    let ovmf_path = "/usr/share/edk2/x64/OVMF.4m.fd";
    let sock_path = "/tmp/qemu_mon_xtask.sock";
    let ppm_path = "/tmp/purent_desktop.ppm";
    let png_path = root.join("target/desktop.png");

    let _ = fs::remove_file(sock_path);
    let _ = fs::remove_file(ppm_path);

    println!("==> [PureNT xtask] Launching QEMU for screen capture...");
    let mut child = Command::new("qemu-system-x86_64")
        .args([
            "-bios",
            ovmf_path,
            "-kernel",
            uefi_binary.to_str().unwrap(),
            "-drive",
            &format!("format=raw,file=fat:rw:{}", esp_dir.display()),
            "-device",
            "VGA,edid=on,xres=1280,yres=720",
            "-display",
            "none",
            "-serial",
            "file:/tmp/purent_serial.log",
            "-monitor",
            &format!("unix:{},server,nowait", sock_path),
            "-m",
            "512M",
        ])
        .spawn()
        .expect("Failed to launch QEMU");

    // Wait for QEMU socket to appear and GUI desktop to fully render
    for _ in 0..50 {
        if Path::new(sock_path).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    std::thread::sleep(std::time::Duration::from_secs(12));

    // Send screendump command via unix socket
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    if let Ok(mut stream) = UnixStream::connect(sock_path) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(format!("screendump {}\n", ppm_path).as_bytes());
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    let _ = child.kill();
    let _ = child.wait();

    if Path::new(ppm_path).exists() {
        // Convert PPM to PNG via python3 PIL
        let py_status = Command::new("python3")
            .args([
                "-c",
                &format!(
                    "from PIL import Image; Image.open('{}').save('{}')",
                    ppm_path,
                    png_path.display()
                ),
            ])
            .status();

        if py_status.map(|s| s.success()).unwrap_or(false) {
            println!("==> [PureNT xtask] Screenshot captured: {}", png_path.display());
        } else {
            println!("==> [PureNT xtask] Raw PPM screenshot saved at {}", ppm_path);
        }
    } else {
        eprintln!("[ERROR] screendump failed to generate {}", ppm_path);
    }
}

fn main() {
    let arg = env::args().nth(1).unwrap_or_else(|| "build".into());
    match arg.as_str() {
        "build" => build(),
        "run" => run(),
        "screenshot" => screenshot(),
        "dwm" => {
            if let Err(error) = dwm::prepare(&project_root(), env::args_os().skip(2)) {
                eprintln!("dwm: {error}");
                std::process::exit(1);
            }
        }
        other => eprintln!("Unknown command: {}. Available: build, run, screenshot, dwm", other),
    }
}
