use eframe::{egui, egui::IconData};
use blackice_proctor::{ProctorApp, network};

fn main() -> Result<(), eframe::Error> {
    // panic hook
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("[main]: PANIC DETECTED! EMERGENCY FIREWALL RESET INITIATED");
        let _ = network::reset_firewall(); 
        original_hook(panic_info);
    }));

    let icon = load_icon(include_bytes!("./app_icon.png"));
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "BlackICE Proctor",
        options,
        Box::new(|_cc| Ok(Box::new(ProctorApp::default()))),
    )
}

fn load_icon(image_bytes: &[u8]) -> IconData {
    let image = image::load_from_memory(image_bytes)
        .expect("Failed to load icon image, is the format supported?")
        .into_rgba8();

    let (width, height) = image.dimensions();
    let rgba = image.into_raw();

    IconData {
        rgba,
        width,
        height,
    }
}