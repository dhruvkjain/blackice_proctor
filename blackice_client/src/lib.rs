use eframe::egui;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

pub mod applications;
pub mod cloud_reporter;
pub mod environment;
pub mod network;

pub use applications::*;
pub use cloud_reporter::*;
pub use environment::*;
pub use network::*;


pub struct ProctorApp {
    net_active: bool,
    proc_active: bool,
    is_loading: bool,
    logs: Vec<String>,

    watchdog_signal: Arc<AtomicBool>,
    dns_signal: Arc<AtomicBool>,

    msg_sender: Sender<AppLogs>,
    msg_receiver: Receiver<AppLogs>,
    reporter_tx: Sender<LogEntry>,

    wfp_guard: Option<network::WfpGuard>,
}

impl Drop for ProctorApp {
    fn drop(&mut self) {
        println!("Application is closing...");

        // stop threads
        self.watchdog_signal.store(false, Ordering::Relaxed);
        self.dns_signal.store(false, Ordering::Relaxed);

        // restore internet
        if self.net_active {
            println!("Restoring Firewall Rules...");
            if let Err(e) = network::reset_firewall() {
                eprintln!("FAILED TO RESTORE FIREWALL: {}", e);
            }
        }
    }
}

impl eframe::App for ProctorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // handle async messages from background threads
        while let Ok(msg) = self.msg_receiver.try_recv() {
            match msg {
                AppLogs::Info(text) => {
                    self.logs.push(format!("> {}", text));
                },

                AppLogs::Error(err) => {
                    self.logs.push(format!("[ERROR]: {}", err));
                    self.is_loading = false; // re-enable buttons
                },

                AppLogs::Violation(v_type, text) => {
                    let level_label = match v_type {
                        ViolationType::Application => "VIOLATION_APP",
                        ViolationType::Network => "VIOLATION_NET",
                        ViolationType::Environment => "VIOLATION_ENV",
                        ViolationType::Other => "VIOLATION_OTH",
                    };

                    self.logs.push(format!("[{:?}] {}", v_type, text));

                    // report to cloud server with category
                    self.report(level_label, &text);
                },

                AppLogs::LockSuccess(guard) => {
                    self.wfp_guard = Some(guard);
                    self.net_active = true;
                    self.is_loading = false;
                    self.logs.push("[network] [wfp]: NETWORK SECURED".into());

                    // start DNS watchdog (has 60s refresher)
                    self.start_dns_watchdog();
                },

                AppLogs::UnlockSuccess => {
                    self.wfp_guard = None; // removes WFP filters
                    self.net_active = false;
                    self.is_loading = false;

                    // stop DNS watchdog
                    self.dns_signal.store(false, Ordering::Relaxed);

                    self.logs.push("[network]: NETWORK UNLOCKED".into());
                },
            }
        }

        // egui UI Rendering
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("");
            ui.add_space(10.0);

            // ------------ Network Control
            ui.group(|ui| {
                ui.heading("1. Network Access");

                if self.is_loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Processing Rules...");
                    });
                } else {
                    let status_text = if self.net_active {
                        "Strict Whitelist Rules"
                    } else {
                        "Open Network"
                    };
                    let color = if self.net_active {
                        egui::Color32::RED
                    } else {
                        egui::Color32::GREEN
                    };
                    ui.colored_label(color, format!("Status: {}", status_text));

                    ui.add_space(5.0);
                    let btn_text = if self.net_active {
                        "Restore Network"
                    } else {
                        "Block Network"
                    };

                    if ui
                        .add_sized([ui.available_width(), 30.0], egui::Button::new(btn_text))
                        .clicked()
                    {
                        self.toggle_network();
                    }
                }
            });

            ui.add_space(10.0);

            // ------------ Processes Control
            ui.group(|ui| {
                ui.heading("2. Processes Monitor");
                let status_text = if self.proc_active {
                    "Monitoring"
                } else {
                    "Idle"
                };
                let color = if self.proc_active {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::GRAY
                };
                ui.colored_label(color, format!("Status: {}", status_text));

                ui.add_space(5.0);
                let btn_text = if self.proc_active {
                    "⏹ Stop Monitor"
                } else {
                    "▶ Start Monitor"
                };
                if ui
                    .add_sized([ui.available_width(), 30.0], egui::Button::new(btn_text))
                    .clicked()
                {
                    self.toggle_process_monitor();
                }
            });

            ui.add_space(10.0);
            ui.separator();
            ui.heading("Event Logs");

            // ------------ Logs
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log in &self.logs {
                        ui.monospace(log);
                    }
                });
        });

        // ensures smooth UI updates during loading/monitoring
        if self.is_loading || self.proc_active {
            ctx.request_repaint();
        }
    }
}

impl ProctorApp {
    pub fn new(reporter_tx: Sender<LogEntry>) -> Self {
        // channel for main and threads communication
        let (tx, rx) = channel::<AppLogs>();

        Self {
            net_active: false,
            proc_active: false,
            is_loading: false,
            logs: vec!["[System Initialized]".into()],
            watchdog_signal: Arc::new(AtomicBool::new(false)),
            dns_signal: Arc::new(AtomicBool::new(false)),
            msg_sender: tx,
            msg_receiver: rx,
            reporter_tx,
            wfp_guard: None,
        }
    }

    fn report(&self, level: &str, msg: &str) {
        let log = LogEntry {
            student_id: "student_123".to_string(), // Replace with dynamic ID
            session_id: "session_abc".to_string(),
            level: level.to_string(),
            message: msg.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        // .send() is non-blocking on unbounded channels, or mostly fast on buffered ones.
        // it simply pushes to the channel memory.
        if let Err(e) = self.reporter_tx.send(log) {
            eprintln!("Failed to queue log: {}", e);
        }
    }

    fn toggle_network(&mut self) {
        if self.is_loading {
            return;
        }
        self.is_loading = true;

        let tx = self.msg_sender.clone();

        if !self.net_active {
            // Locking Logic
            self.log("[network]: Initializing Lockdown (Resolving DNS & Hashing Apps)...");

            thread::spawn(move || {
                // initialize WFP (App ID Hashing)
                tx.send(AppLogs::Info(
                    "[network] [wfp]: Generating App IDs...".into(),
                ))
                .ok();

                let guard = match network::WfpGuard::new() {
                    Ok(g) => {
                        if let Err(e) = g.apply_ale_lockdown() {
                            tx.send(AppLogs::Error(format!("[network] {}", e))).ok();
                            return;
                        }
                        g
                    }
                    Err(e) => {
                        tx.send(AppLogs::Error(format!("[network] {}", e))).ok();
                        return;
                    }
                };

                // enable firewall (DNS Resolution)
                tx.send(AppLogs::Info(
                    "[network] [firewall rules]: Applying IP Rules...".into(),
                ))
                .ok();

                match network::apply_rules() {
                    Ok(msg) => {
                        tx.send(AppLogs::Info(format!(
                            "[network] [firewall rules]: {}",
                            msg
                        )))
                        .ok();
                        // on success, send the guard to main thread
                        tx.send(AppLogs::LockSuccess(guard)).ok();
                    }
                    Err(e) => {
                        tx.send(AppLogs::Error(format!("[network] [firewall rules]: {}", e)))
                            .ok();
                    }
                }
            });
        } else {
            // UnLocking Logic
            self.log("[network]: Disabling Locks...");
            thread::spawn(move || match network::reset_firewall() {
                Ok(_) => tx.send(AppLogs::UnlockSuccess).ok(),
                Err(e) => tx
                    .send(AppLogs::Error(format!(
                        "[network] [firewall rules] Unlock Failed: {}",
                        e
                    )))
                    .ok(),
            });
        }
    }

    fn start_dns_watchdog(&mut self) {
        self.dns_signal.store(true, Ordering::Relaxed);
        let signal = self.dns_signal.clone();

        thread::spawn(move || {
            while signal.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_secs(60));

                if !signal.load(Ordering::Relaxed) {
                    break;
                }

                if let Err(e) = network::refresh_whitelist() {
                    eprintln!("[ERROR] DNS Watchdog Error: {}", e);
                } else {
                    println!("DNS Watchdog: Rules Refreshed.");
                }
            }
        });
    }

    fn toggle_process_monitor(&mut self) {
        if !self.proc_active {
            self.proc_active = true;
            self.watchdog_signal.store(true, Ordering::Relaxed);

            let tx = self.msg_sender.clone();
            let signal = self.watchdog_signal.clone();

            // Security Thread
            thread::spawn(move || {
                tx.send(AppLogs::Info(
                    "[security]: Security and Process Monitor Started".into(),
                ))
                .ok();

                // inital scan for VM, RDP, multiple monitors
                if let Some(violation) = environment::scan_environment() {
                    tx.send(AppLogs::Violation(ViolationType::Environment, format!(
                        "[security]: {}",
                        violation
                    )))
                    .ok();
                }

                let (local_tx, local_rx) = channel::<AppLogs>();
                let signal_for_app_mon = signal.clone();

                thread::spawn(move || {
                    applications::start_monitor(signal_for_app_mon, local_tx);
                });

                while signal.load(Ordering::Relaxed) {
                    environment::clear_clipboard();

                    // checking for RDP (Remote Desktop) dynamically
                    use windows::Win32::UI::WindowsAndMessaging::{
                        GetSystemMetrics, SM_REMOTESESSION,
                    };
                    unsafe {
                        if GetSystemMetrics(SM_REMOTESESSION) != 0 {
                            tx.send(AppLogs::Violation(
                                ViolationType::Environment,
                                "[security] REMOTE SESSION DETECTED".into(),
                            ))
                            .ok();
                        }
                    }

                    while let Ok(msg) = local_rx.try_recv() {
                        tx.send(msg).ok();
                    }

                    // sleep briefly to prevent full CPU usage
                    thread::sleep(std::time::Duration::from_millis(500));
                }
            });
        } else {
            self.proc_active = false;
            self.watchdog_signal.store(false, Ordering::Relaxed);
            self.log("[processes]: Stopping Monitor Thread...");
        }
    }

    fn log(&mut self, msg: &str) {
        self.logs.push(format!("> {}", msg));
    }
}
