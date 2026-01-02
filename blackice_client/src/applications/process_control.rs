use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::thread;
use std::sync::mpsc::Sender;
use std::collections::HashSet;

use windows::core::BOOL;
use windows::Win32::Foundation::{HANDLE, CloseHandle, HWND, LPARAM};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible
};

use crate::cloud_reporter::{AppLogs, ViolationType};


// STRICT PATH BINDING
const STRICT_PATHS: &[(&str, &str)] = &[
    ("chrome.exe", "google\\chrome"),
    ("brave.exe", "brave-browser"),
    ("msedge.exe", "microsoft\\edge"),
    ("firefox.exe", "mozilla firefox"),
    ("explorer.exe", "windows\\explorer.exe"),
    ("notepad.exe", "windows\\system32"),
];

// EXACT NAME MATCH IGNORE LIST
const WHITELIST_NAMES: &[&str] = &[
    // ------------ Windows Kernel / Virtual
    "secure system", "registry", "memory compression", "system",
    "monotificationux.exe",          // Windows Update Notifications
    
    // ------------ Windows Modern UI Components
    "textinputhost.exe",             // On-screen keyboard/emoji logic
    "lockapp.exe",                   // Lock screen
    "crossdeviceresume.exe",         // Phone Link
    "shellexperiencehost.exe",       // Start menu / Taskbar
    "startmenuexperiencehost.exe",   // Start menu
    "searchhost.exe",                // Windows Search
    "systemsettings.exe",            // Windows Settings App
    "smartscreen.exe",               // Windows Defender SmartScreen
    
    // ------------ Background Services
    "postgres.exe", "pg_ctl.exe", "wslservice.exe",
    "docker.exe", "dockerd.exe", "officeclicktorun.exe", "onedrive.exe",
    "uihost.exe" // Mcafee
];

// PARTIAL MATCH IGNORE LIST
const WHITELIST_PARTIALS: &[&str] = &[
    "intel", "dell", "nvidia", "amd", "realtek", 
    "google", "microsoft", "windows", "adsk", // Autodesk
    "jhi_", "ipf", "rstmw", "igcc", "wudf",   // Driver hosts
    "fontdrv", "mpdefender", "msmpeng",       // Windows Defender/Fonts
    "rust-analyzer", "onedrive",
];

// BANNED WINDOW TITLES (even if user renames .exe file the windows title is set programatically by appliaction developer)
const BANNED_TITLES: &[&str] = &[
    "cheat engine",
    "proton vpn", 
    "speedhack", 
    "wireshark",
    "chatgpt", 
    "openai", 
    "claude", 
    "gemini", 
    "discord", 
    "whatsapp", 
    "telegram",
    "stack overflow",
    "cursor"
];

pub fn start_monitor(keep_running: Arc<AtomicBool>, tx: Sender<AppLogs>) {
    let _ = tx.send(AppLogs::Info("[application]: OPTIMIZED MONITOR STARTED".to_string()));
    
    // caching the lists for speed
    // TODO: cache other too
    let exact_set: HashSet<&str> = WHITELIST_NAMES.iter().cloned().collect();
    
    while keep_running.load(Ordering::Relaxed) {
        unsafe { 
            // scan processes (files and paths)
            scan_optimized(&tx, &exact_set);
            // scan 'open window' / 'visible' Windows titles
            scan_window_titles(&tx);
        }
        // increased sleep to 3 seconds to let CPU cool down
        thread::sleep(Duration::from_secs(3)); 
    }
    let _ = tx.send(AppLogs::Info("[application]: MONITOR STOPPED".to_string()));
}


// ------------ Helper functions
unsafe fn scan_window_titles(tx: &Sender<AppLogs>) {
    // EnumWindows takes a C-style callback function
    // we pass the Sender `tx` as a pointer (LPARAM) so the callback can use it
    let param = LPARAM(tx as *const Sender<AppLogs> as isize);
    EnumWindows(Some(enum_window_callback), param);
}

// this function is called by Windows for every single 'open window' / 'visible'
unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // ignore invisible windows (background apps)
    // in Windows almost everyhing is a window including windows internel services 
    // therefore ignore all non UI windows
    if !IsWindowVisible(hwnd).as_bool() {
        return true.into(); // continue to next window
    }

    // get the Window Title
    let mut buffer = [0u16; 512];
    let len = GetWindowTextW(hwnd, &mut buffer);

    if len > 0 {
        let title = String::from_utf16_lossy(&buffer[..len as usize]).to_lowercase();
        for banned_word in BANNED_TITLES {
            if title.contains(banned_word) {
                let mut pid = 0;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
                let tx = &*(lparam.0 as *const Sender<AppLogs>);
                let _ = tx.send(AppLogs::Violation(ViolationType::Application, format!("[appliaction] [security] BANNED WINDOW: '{}' (PID: {})", title, pid)));
                break; 
            }
        }
    }

    true.into() // for enumeration
}

unsafe fn scan_optimized(tx: &Sender<AppLogs>, exact_set: &HashSet<&str>) {
    let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
        Ok(h) => h,
        Err(_) => return,
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    if Process32First(snapshot, &mut entry).is_ok() {
        loop {
            let pid = entry.th32ProcessID;
            
            if pid > 4 { 
                let name_c = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr());
                let name_str = name_c.to_string_lossy().to_lowercase();
                
                let mut is_safe = false;
                for (rule_name, rule_path) in STRICT_PATHS {
                    if name_str == *rule_name {
                        let real_path = get_process_path(pid).to_lowercase();
                        if !real_path.contains(rule_path) {
                            let _ = tx.send(AppLogs::Violation(ViolationType::Application, format!(
                                "[application] [security] MASQUERADE(renaming cheat) DETECTED: '{}' running from '{}' (Expected: {})", 
                                name_str, real_path, rule_path
                            )));
                        }
                        // if path matches, it is explicitly safe
                        is_safe = true;
                        break;
                    }
                }

                // for exact match
                if exact_set.contains(name_str.as_str()) { is_safe = true; }
                
                // for partial match
                if !is_safe {
                    if WHITELIST_PARTIALS.iter().any(|&part| name_str.contains(part)) {
                        is_safe = true;
                    }
                }

                // for path check
                if !is_safe {
                    let path = get_process_path(pid).to_lowercase();
                    
                    if path.is_empty() {
                        // if here access denied => usually means a System Process or Anti-Cheat
                        // for now we ignore
                        // let _ = tx.send(format!("[application] [security]: LOCKED PATH detected: {}", name_str));
                    } else {
                        // here we have removed "program files" from this list to catch Cursor, Obsidian etc..
                        // TODO: think if I can improve this
                        let is_system_dir = path.contains("windows\\system32") || 
                                            path.contains("windows\\syswow64") ||
                                            path.contains("windows\\systemapps") ||
                                            path.contains("windows\\immersivecontrolpanel") ||
                                            path.contains("program files\\windowsapps") ||
                                            path.contains("microsoft\\edgewebview") ||
                                            path.contains("windows\\uus");

                        if !is_system_dir {
                             let _ = tx.send(AppLogs::Violation(ViolationType::Application, format!("[application] [security] SUSPICIOUS APP: '{}' in '{}'", name_str, path)));
                        }
                    }
                }
            }

            if Process32Next(snapshot, &mut entry).is_err() { break; }
        }
    }
    let _ = CloseHandle(snapshot);
}

// this function is only called for unknown apps
unsafe fn get_process_path(pid: u32) -> String {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid).unwrap_or(HANDLE::default());
    if snapshot.is_invalid() { return String::new(); }

    let mut entry = MODULEENTRY32 {
        dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };

    if Module32First(snapshot, &mut entry).is_ok() {
        let path = std::ffi::CStr::from_ptr(entry.szExePath.as_ptr())
            .to_string_lossy()
            .to_string();
        let _ = CloseHandle(snapshot);
        return path;
    }
    let _ = CloseHandle(snapshot);
    String::new()
}