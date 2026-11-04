//! Per-user native desktop installation. Connection arguments are written only
//! to the local desktop entry; no workstation settings belong in the source.
use std::io;
#[cfg(target_os = "linux")]
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub(super) fn startup_error(message: String) -> Result<(), Box<dyn std::error::Error>> {
    let data = super::data_dir();
    let _ = genyra_common::save_private(&data, "desktop-error.log", message.as_bytes());
    struct Failure {
        message: String,
        path: std::path::PathBuf,
    }
    impl eframe::App for Failure {
        fn update(&mut self, ctx: &eframe::egui::Context, _: &mut eframe::Frame) {
            eframe::egui::CentralPanel::default().show(ctx,|ui|{
                ui.add_space(14.);ui.heading("Genyra Snitch could not connect");ui.add_space(12.);
                ui.label(&self.message);ui.add_space(12.);
                ui.label("Check that the collector is running and its token file is accessible, then open Genyra Snitch again.");
                ui.label(format!("Details: {}",self.path.display()));
                if ui.button("Copy error").clicked(){ctx.copy_text(self.message.clone());}
                if ui.button("Close").clicked(){ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close);}
            });
        }
    }
    let options = eframe::NativeOptions {
        vsync: super::desktop_vsync(false),
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([650., 320.])
            .with_app_id("com.genyra.snitch"),
        ..Default::default()
    };
    eframe::run_native(
        "Genyra Snitch",
        options,
        Box::new(move |_| {
            Ok(Box::new(Failure {
                message,
                path: data.join("desktop-error.log"),
            }))
        }),
    )?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn executable_copy(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut staged = tempfile::NamedTempFile::new_in(destination.parent().unwrap())?;
    io::copy(&mut fs::File::open(source)?, &mut staged)?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    staged.as_file().sync_all()?;
    staged.persist(destination).map_err(|e| e.error)?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn desktop_argument(value: &str) -> io::Result<String> {
    if value.chars().any(char::is_control) {
        return Err(io::Error::other(
            "Launcher arguments cannot contain control characters",
        ));
    }
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%");
    Ok(format!("\"{escaped}\""))
}
#[cfg(target_os = "linux")]
pub(super) fn desktop(args: &[String]) -> io::Result<()> {
    let home = PathBuf::from(
        std::env::var_os("HOME").ok_or_else(|| io::Error::other("No home directory"))?,
    );
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"));
    let bundle = home
        .join(".local/lib/genyra-snitch")
        .join(env!("CARGO_PKG_VERSION"));
    fs::create_dir_all(&bundle)?;
    let source = std::env::current_exe()?;
    let collector = super::lifecycle::backend().map_err(io::Error::other)?;
    let desktop = bundle.join("genyra-snitch-desktop");
    executable_copy(&source, &desktop)?;
    executable_copy(&collector, &bundle.join("genyra-snitch"))?;
    let notices = bundle.join("licenses");
    fs::create_dir_all(&notices)?;
    for (name, bytes) in [
        ("LICENSE", include_bytes!("../../LICENSE").as_slice()),
        ("NOTICE", include_bytes!("../../NOTICE").as_slice()),
        (
            "THIRD_PARTY_NOTICES.md",
            include_bytes!("../../THIRD_PARTY_NOTICES.md").as_slice(),
        ),
        (
            "OFL-Noto.txt",
            include_bytes!("../assets/fonts/OFL-Noto.txt").as_slice(),
        ),
    ] {
        fs::write(notices.join(name), bytes)?;
    }
    // Keep menu shortcuts stable across versioned updates. Publish the link
    // only after both binaries are installed, without replacing a real folder.
    let current = bundle.parent().unwrap().join("current");
    if fs::symlink_metadata(&current).is_ok_and(|m| !m.file_type().is_symlink()) {
        return Err(io::Error::other(
            "The application current path is not a symbolic link",
        ));
    }
    let staging = tempfile::tempdir_in(bundle.parent().unwrap())?;
    let staged_link = staging.path().join("current");
    std::os::unix::fs::symlink(&bundle, &staged_link)?;
    fs::rename(staged_link, &current)?;
    let icons = data.join("icons/hicolor/256x256/apps");
    fs::create_dir_all(&icons)?;
    fs::write(
        icons.join("genyra-snitch.png"),
        include_bytes!("../../ui/public/brand/genyra-icon.png"),
    )?;
    let mut launch = vec![desktop_argument(
        &current.join("genyra-snitch-desktop").to_string_lossy(),
    )?];
    for name in ["--connect", "--token-file", "--data-dir"] {
        if let Some(pair) = args.windows(2).find(|pair| pair[0] == name) {
            launch.push(desktop_argument(name)?);
            launch.push(desktop_argument(&pair[1])?);
        }
    }
    if args.iter().any(|s| s == "--read-only") {
        launch.push("--read-only".into());
    }
    let entry=format!("[Desktop Entry]\nVersion=1.0\nType=Application\nName=Genyra Snitch\nGenericName=Network monitor\nComment=Live network visibility and application security by Genyra LLC\nExec={}\nIcon=genyra-snitch\nTerminal=false\nStartupNotify=true\nStartupWMClass=com.genyra.snitch\nCategories=Network;Monitor;\nKeywords=network;traffic;firewall;security;Genyra;Snitch;\n",launch.join(" "));
    let applications = data.join("applications");
    fs::create_dir_all(&applications)?;
    let path = applications.join("com.genyra.snitch.desktop");
    let mut staged = tempfile::NamedTempFile::new_in(&applications)?;
    staged.write_all(entry.as_bytes())?;
    staged.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    staged.persist(&path).map_err(|e| e.error)?;
    println!("Installed Genyra Snitch: {}", path.display());
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub(super) fn desktop(_: &[String]) -> io::Result<()> {
    Err(io::Error::other(
        "--install is the Linux app-menu installer; use your platform's native distribution",
    ))
}
