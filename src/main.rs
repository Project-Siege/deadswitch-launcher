use eframe::egui;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

#[derive(Clone)]
enum Launcher {
    Epic,
    Steam,
    Unknown,
}

#[derive(Clone)]
struct GameEntry {
    name: String,
    exe_path: String,
    launcher: Launcher,
    steam_app_id: Option<String>,
}

#[derive(Default)]
struct KillrsApp {
    status: Arc<Mutex<String>>,
    games: Vec<GameEntry>,
    monitor_flags: Arc<Mutex<Vec<bool>>>,
}

impl KillrsApp {
    fn new() -> Self {
        let games = detect_games();
        let monitor_flags = Arc::new(Mutex::new(vec![false; games.len()]));
        Self {
            games,
            monitor_flags,
            ..Default::default()
        }
    }
}

impl eframe::App for KillrsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Killrs Game Launcher");

            if ui.button("🔍 Scan for Installed Games").clicked() {
                let new_games = detect_games();
                self.games = new_games.clone();
                self.monitor_flags = Arc::new(Mutex::new(vec![false; new_games.len()]));
                *self.status.lock().unwrap() = "Game list refreshed.".into();
            }

            ui.label("Status:");
            ui.label(self.status.lock().unwrap().as_str());

            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, game) in self.games.iter().enumerate() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(&game.name);
                            if ui.button("Launch").clicked() {
                                let status = self.status.clone();
                                let monitor = self.monitor_flags.clone();
                                let game = game.clone();
                                thread::spawn(move || {
                                    launch_game(game, status, monitor, i);
                                });
                            }
                            if ui.button("Exit Game").clicked() {
                                let exe_name = PathBuf::from(&game.exe_path)
                                    .file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .to_string();
                                let _ = Command::new("taskkill")
                                    .args(["/F", "/IM", &exe_name])
                                    .output();
                                *self.status.lock().unwrap() = format!("{} force killed.", game.name);
                            }
                            ui.checkbox(&mut self.monitor_flags.lock().unwrap()[i], "Monitor");
                        });
                    });
                }
            });
        });

        ctx.request_repaint();
    }
}

fn detect_games() -> Vec<GameEntry> {
    let mut games = vec![];

    let rl_path = "C:\\Program Files\\Epic Games\\RocketLeague\\Binaries\\Win64\\RocketLeague.exe";
    if fs::metadata(rl_path).is_ok() {
        games.push(GameEntry {
            name: "Rocket League".into(),
            exe_path: rl_path.into(),
            launcher: Launcher::Epic,
            steam_app_id: None,
        });
    }

    let epic_root = "C:\\Program Files\\Epic Games";
    if let Ok(entries) = fs::read_dir(epic_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.to_string_lossy().contains("RocketLeague") {
                if let Some(exe_path) = find_exe_in_dir(&path) {
                    games.push(GameEntry {
                        name: path.file_name().unwrap().to_string_lossy().to_string(),
                        exe_path: exe_path.to_string_lossy().to_string(),
                        launcher: Launcher::Epic,
                        steam_app_id: None,
                    });
                }
            }
        }
    }

    let steam_common = "C:\\Program Files (x86)\\Steam\\steamapps\\common";
    let steam_apps = "C:\\Program Files (x86)\\Steam\\steamapps";
    if let Ok(entries) = fs::read_dir(steam_common) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let folder_name = path.file_name().unwrap().to_string_lossy().to_string();
                let app_id = find_app_id(&folder_name, steam_apps);
                if let Some(exe_path) = find_exe_in_dir(&path) {
                    games.push(GameEntry {
                        name: folder_name,
                        exe_path: exe_path.to_string_lossy().to_string(),
                        launcher: Launcher::Steam,
                        steam_app_id: app_id,
                    });
                }
            }
        }
    }

    games
}

fn find_exe_in_dir(dir: &Path) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "exe").unwrap_or(false) {
                return Some(path);
            }
        }
    }
    None
}

fn find_app_id(folder_name: &str, steam_apps: &str) -> Option<String> {
    if let Ok(entries) = fs::read_dir(steam_apps) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "acf").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains(&format!("\"installdir\"\t\t\"{}\"", folder_name)) {
                        if let Some(file_name) = path.file_name() {
                            let name = file_name.to_string_lossy();
                            if name.starts_with("appmanifest_") {
                                return Some(
                                    name.trim_start_matches("appmanifest_")
                                        .trim_end_matches(".acf")
                                        .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn get_pid(process_name: &str) -> Option<u32> {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", process_name)])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.to_lowercase().starts_with(&process_name.to_lowercase()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                return parts[1].parse::<u32>().ok();
            }
        }
    }

    None
}

fn is_backgrounded_or_unresponsive(pid: u32) -> bool {
    let script = format!(
        r#"
        $p = Get-Process -Id {pid}
        if ($p.MainWindowHandle -eq 0 -or !$p.Responding) {{ return $true }} else {{ return $false }}
        "#,
        pid = pid
    );

    let output = Command::new("powershell")
        .args(["-Command", &script])
        .output();

    match output {
        Ok(out) => {
            let result = String::from_utf8_lossy(&out.stdout);
            result.trim().eq_ignore_ascii_case("True")
        }
        Err(_) => false,
    }
}

fn launch_game(
    game: GameEntry,
    status: Arc<Mutex<String>>,
    monitor_flags: Arc<Mutex<Vec<bool>>>,
    index: usize,
) {
    match game.launcher {
        Launcher::Epic => {
            let epic_launcher = "C:\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Binaries\\Win32\\EpicGamesLauncher.exe";
            let _ = Command::new(epic_launcher).spawn();
            *status.lock().unwrap() = format!("Epic Launcher started. Waiting for {}...", game.name);
        }
        Launcher::Steam => {
            if let Some(app_id) = &game.steam_app_id {
                let _ = Command::new("cmd")
                    .args(["/C", &format!("start steam://rungameid/{}", app_id)])
                    .spawn();
                *status.lock().unwrap() = format!("Steam launch triggered for {}...", game.name);
            } else {
                *status.lock().unwrap() = format!("Steam AppID missing for {}.", game.name);
                return;
            }
        }
        Launcher::Unknown => {
            let _ = Command::new(&game.exe_path).spawn();
            *status.lock().unwrap() = format!("Direct launch for {}...", game.name);
        }
    }

    let exe_name = PathBuf::from(&game.exe_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let mut pid: Option<u32> = None;
    for _ in 0..180 {
        if let Some(found_pid) = get_pid(&exe_name) {
            pid = Some(found_pid);
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }

    if let Some(_) = pid {
        *status.lock().unwrap() = format!("{} started successfully.", game.name);
    } else {
        *status.lock().unwrap() = format!("{} did not start.", game.name);
        return;
    }

    if !monitor_flags.lock().unwrap()[index] {
        return;
    }

    let mut stable_window_seen = false;
    let mut stable_window_count = 0;
    let mut consecutive_failures = 0;
    let failure_threshold = 5;

    loop {
        match get_pid(&exe_name) {
            Some(current_pid) => {
                if !is_backgrounded_or_unresponsive(current_pid) {
                    if stable_window_seen {
                        consecutive_failures = 0;
                    } else {
                        stable_window_count += 1;
                        if stable_window_count >= 10 {
                            stable_window_seen = true;
                            *status.lock().unwrap() = format!("{} window stabilized. Monitoring...", game.name);
                        }
                    }
                } else if stable_window_seen {
                    consecutive_failures += 1;
                    if consecutive_failures >= failure_threshold {
                        *status.lock().unwrap() = format!("{} is unresponsive. Force killing...", game.name);
                        let _ = Command::new("taskkill")
                            .args(["/F", "/IM", &exe_name])
                            .output();
                        break;
                    }
                }
            }
            None => {
                if stable_window_seen {
                    *status.lock().unwrap() = format!("{} fully exited.", game.name);
                    break;
                }
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    *status.lock().unwrap() = format!("{} session complete.", game.name);
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 540.0])
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native("Killrs Launcher", options, Box::new(|_cc| Box::new(KillrsApp::new())))
}
