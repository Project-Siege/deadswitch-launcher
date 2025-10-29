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
    game_dir: String,
}

#[derive(Default)]
struct DeadSwitchApp {
    status: Arc<Mutex<String>>,
    games: Vec<GameEntry>,
    monitor_flags: Arc<Mutex<Vec<bool>>>,
}

impl DeadSwitchApp {
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

impl eframe::App for DeadSwitchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DeadSwitch Launcher");

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
                                let game_dir = game.game_dir.clone();
                                let game_name = game.name.clone();
                                let status = self.status.clone();
                                thread::spawn(move || {
                                    *status.lock().unwrap() = format!("Searching for {} processes...", game_name);
                                    
                                    if let Some((exe_name, _)) = find_game_process(&game_dir) {
                                        *status.lock().unwrap() = format!("Killing {}...", exe_name);
                                        let result = Command::new("taskkill")
                                            .args(["/F", "/IM", &exe_name])
                                            .output();
                                        
                                        match result {
                                            Ok(_) => *status.lock().unwrap() = format!("{} killed.", game_name),
                                            Err(e) => *status.lock().unwrap() = format!("Error killing {}: {}", game_name, e),
                                        }
                                    } else {
                                        *status.lock().unwrap() = format!("{} is not running.", game_name);
                                    }
                                });
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

    let epic_root = "C:\\Program Files\\Epic Games";
    if let Ok(entries) = fs::read_dir(epic_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(exe_path) = find_exe_in_dir(&path) {
                    games.push(GameEntry {
                        name: path.file_name().unwrap().to_string_lossy().to_string(),
                        exe_path: exe_path.to_string_lossy().to_string(),
                        launcher: Launcher::Epic,
                        steam_app_id: None,
                        game_dir: path.to_string_lossy().to_string(),
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
                        name: folder_name.clone(),
                        exe_path: exe_path.to_string_lossy().to_string(),
                        launcher: Launcher::Steam,
                        steam_app_id: app_id,
                        game_dir: path.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }

    games
}

fn find_exe_in_dir(dir: &Path) -> Option<PathBuf> {
    fn find_exe_recursive(dir: &Path, depth: usize) -> Option<PathBuf> {
        if depth > 5 {
            return None;
        }
        
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().map(|ext| ext == "exe").unwrap_or(false) {
                    return Some(path);
                }
            }
            
            for entry in fs::read_dir(dir).ok()?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(exe) = find_exe_recursive(&path, depth + 1) {
                        return Some(exe);
                    }
                }
            }
        }
        None
    }
    
    find_exe_recursive(dir, 0)
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

fn get_all_exes_in_dir(dir: &Path) -> Vec<String> {
    let mut exes = Vec::new();
    
    fn collect_exes(dir: &Path, exes: &mut Vec<String>, depth: usize) {
        if depth > 5 {
            return;
        }
        
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "exe" {
                            if let Some(name) = path.file_name() {
                                exes.push(name.to_string_lossy().to_string());
                            }
                        }
                    }
                } else if path.is_dir() {
                    let dir_name = path.file_name().unwrap().to_string_lossy().to_lowercase();
                    // Skip known non-game directories
                    if !dir_name.contains("easyanticheat") && !dir_name.contains("battleye") {
                        collect_exes(&path, exes, depth + 1);
                    }
                }
            }
        }
    }
    
    collect_exes(dir, &mut exes, 0);
    exes
}

fn find_game_process(game_dir: &str) -> Option<(String, u32)> {
    // Method 1: Check all executables in the game directory against running processes
    let game_path = Path::new(game_dir);
    let all_exes = get_all_exes_in_dir(game_path);
    
    // Filter out common non-game executables (more comprehensive for Epic Games)
    let excluded = [
        "unins", "crash", "report", "setup", "install", "update", 
        "easyanticheat", "eac", "battleye", "be",
        "epicgameslauncher", "launcher", "bootstrapper",
        "ucrtbase", "msvcp", "vcruntime", "d3d",
        "repair", "prerequisite", "redist", "_be", "_eac"
    ];
    
    // First pass: Try to find game executables (excluding utilities)
    for exe_name in &all_exes {
        let lower = exe_name.to_lowercase();
        
        // Skip excluded executables
        if excluded.iter().any(|ex| lower.contains(ex)) {
            continue;
        }
        
        if let Some(pid) = get_pid(exe_name) {
            return Some((exe_name.clone(), pid));
        }
    }
    
    // Second pass: If nothing found, try all executables except the most obvious non-games
    let critical_excluded = ["easyanticheat", "eac_launcher", "battleye", "epicgameslauncher"];
    for exe_name in &all_exes {
        let lower = exe_name.to_lowercase();
        
        if critical_excluded.iter().any(|ex| lower.contains(ex)) {
            continue;
        }
        
        if let Some(pid) = get_pid(exe_name) {
            return Some((exe_name.clone(), pid));
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

    let mut actual_exe_name = exe_name.clone();
    let mut pid: Option<u32> = None;
    
    for attempt in 0..180 {
        if let Some(found_pid) = get_pid(&exe_name) {
            actual_exe_name = exe_name.clone();
            pid = Some(found_pid);
            *status.lock().unwrap() = format!("{} process found: {}", game.name, exe_name);
            break;
        }
        
        if let Some((found_exe, found_pid)) = find_game_process(&game.game_dir) {
            actual_exe_name = found_exe.clone();
            pid = Some(found_pid);
            *status.lock().unwrap() = format!("{} process found: {}", game.name, found_exe);
            break;
        }
        
        if attempt % 10 == 0 && attempt > 0 {
            *status.lock().unwrap() = format!("Waiting for {} ({} seconds)...", game.name, attempt / 2);
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
        // Check if the actual process is still running
        let current_pid_opt = get_pid(&actual_exe_name)
            .or_else(|| find_game_process(&game.game_dir).map(|(new_exe, pid)| {
                // Update the tracked exe if we find a different one
                actual_exe_name = new_exe;
                pid
            }));
        
        match current_pid_opt {
            Some(current_pid) => {
                if !is_backgrounded_or_unresponsive(current_pid) {
                    if stable_window_seen {
                        consecutive_failures = 0;
                    } else {
                        stable_window_count += 1;
                        if stable_window_count >= 10 {
                            stable_window_seen = true;
                            *status.lock().unwrap() = format!("{} window stabilized. Monitoring...", game.name);
                        } else if stable_window_count % 3 == 0 {
                            *status.lock().unwrap() = format!("{} waiting for window stability... ({}/10)", game.name, stable_window_count);
                        }
                    }
                } else if stable_window_seen {
                    consecutive_failures += 1;
                    if consecutive_failures >= failure_threshold {
                        *status.lock().unwrap() = format!("{} is unresponsive. Force killing...", game.name);
                        let _ = Command::new("taskkill")
                            .args(["/F", "/IM", &actual_exe_name])
                            .output();
                        break;
                    }
                }
            }
            None => {
                if stable_window_seen {
                    *status.lock().unwrap() = format!("{} fully exited.", game.name);
                    break;
                } else {
                    // Process died before stabilizing
                    *status.lock().unwrap() = format!("{} process exited early.", game.name);
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
    eframe::run_native("DeadSwitch Launcher", options, Box::new(|_cc| Box::new(DeadSwitchApp::new())))
}
