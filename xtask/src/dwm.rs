use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

const MODULES: &[&str] = &[
    "dwm.exe",
    "dwmcore.dll",
    "uDWM.dll",
    "dwmapi.dll",
    "dwmredir.dll",
    "d3d9.dll",
    "d3d10.dll",
    "d3d10core.dll",
    "d3d10_1.dll",
    "d3d10_1core.dll",
    "d3d10warp.dll",
    "dxgi.dll",
    "drivers/dxg.sys",
    "drivers/dxgkrnl.sys",
    "drivers/dxgmms1.sys",
];

pub fn prepare(root: &Path, mut args: impl Iterator<Item = OsString>) -> Result<(), String> {
    let bundle = root.join("refs/win7_7601_x64/dwm");
    if let Some(image) = args.next() {
        let index = args.next().ok_or("usage: xtask dwm [install.esd INDEX]")?;
        if args.next().is_some() {
            return Err("usage: xtask dwm [install.esd INDEX]".into());
        }
        fs::create_dir_all(&bundle).map_err(|e| e.to_string())?;
        let status = Command::new("wimlib-imagex")
            .arg("extract")
            .arg(image)
            .arg(index)
            .args(
                MODULES
                    .iter()
                    .map(|name| format!("/Windows/System32/{name}")),
            )
            .args(["--no-globs", "--no-acls", "--no-attributes", "--dest-dir"])
            .arg(&bundle)
            .status()
            .map_err(|e| format!("wimlib-imagex: {e}"))?;
        if !status.success() {
            return Err(format!("wimlib-imagex extract failed ({status})"));
        }
    }

    let staged: BTreeSet<_> = MODULES
        .iter()
        .map(|path| basename(path).to_ascii_lowercase())
        .collect();
    let mut external = BTreeSet::new();
    for path in MODULES {
        let image = bundle.join(basename(path));
        let output = Command::new("llvm-readobj")
            .args(["--file-headers", "--coff-imports"])
            .arg(&image)
            .output()
            .map_err(|e| format!("llvm-readobj: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "{}: {}",
                image.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let report = String::from_utf8_lossy(&output.stdout);
        if !report
            .lines()
            .any(|line| line.trim() == "Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)")
        {
            return Err(format!("{} is not an AMD64 PE image", image.display()));
        }

        println!("{}", basename(path));
        for ((delayed, library), symbols) in imports(&report) {
            let in_bundle = staged.contains(&library);
            if !in_bundle {
                external.insert(library.clone());
            }
            let kind = if delayed { "delay" } else { "static" };
            let location = if in_bundle { "bundle" } else { "external" };
            let ordinals = symbols
                .iter()
                .filter(|symbol| symbol.starts_with('#'))
                .count();
            println!(
                "  {kind:6} {library:42} {location:8} {:3} imports ({ordinals} by ordinal)",
                symbols.len()
            );
        }
    }
    println!(
        "{} external libraries across the DWM bundle",
        external.len()
    );
    Ok(())
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap()
}

fn imports(report: &str) -> BTreeMap<(bool, String), Vec<String>> {
    let mut dependencies = BTreeMap::<_, Vec<_>>::new();
    let mut delayed = false;
    let mut library = None;
    for line in report.lines() {
        match line {
            "Import {" | "DelayImport {" => {
                delayed = line == "DelayImport {";
                library = None;
            }
            "}" => library = None,
            _ => {
                if let Some(name) = line.strip_prefix("  Name: ") {
                    library = Some(name.to_ascii_lowercase());
                }
                if let (Some(name), Some(symbol)) =
                    (&library, line.trim_start().strip_prefix("Symbol:"))
                {
                    let symbol = symbol.trim();
                    let key = match symbol.rsplit_once('(') {
                        Some((name, ordinal)) if name.trim().is_empty() => {
                            format!("#{}", ordinal.trim_end_matches(')'))
                        }
                        Some((name, _)) => name.trim_end().to_owned(),
                        None => symbol.to_owned(),
                    };
                    dependencies
                        .entry((delayed, name.clone()))
                        .or_default()
                        .push(key);
                }
            }
        }
    }
    dependencies
}
