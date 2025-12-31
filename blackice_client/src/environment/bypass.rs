use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, 
    SM_REMOTESESSION, 
    SM_CMONITORS
};
use windows::Win32::System::DataExchange::{OpenClipboard, EmptyClipboard, CloseClipboard};
use raw_cpuid::CpuId;
use super::vpn;

pub struct SecurityCheck {
    pub vm_vendor: Option<String>,
    pub is_remote: bool,
    pub monitor_count: i32,
    pub vpn_detected: Option<String>,
}

impl SecurityCheck {
    pub fn check() -> Self {
        Self {
            vm_vendor: detect_vm(),
            is_remote: unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 },
            monitor_count: unsafe { GetSystemMetrics(SM_CMONITORS) },
            vpn_detected: vpn::scan_for_vpn(),
        }
    }
}

fn detect_vm() -> Option<String> {
    let cpuid = CpuId::new();
    
    // check if Hypervisor bit is set
    // if this is false, it's definitely bare metal (or a very stealthy VM)
    let has_hypervisor = cpuid.get_feature_info()
        .map(|info| info.has_hypervisor())
        .unwrap_or(false);

    if !has_hypervisor {
        return None;
    }

    // check the Hypervisor Vendor ID
    if let Some(hv) = cpuid.get_hypervisor_info() {
        // raw_cpuid creates a 12-char string from registers ebx, ecx, edx
        // We can't access the string directly easily in older versions, 
        // but we can check the registers or use debug output.
        // The safest way in Rust 'raw_cpuid' is to match specific signatures.
        
        // This relies on internal register values, but raw_cpuid usually doesn't expose the string 
        // directly in a safe cross-platform way without bit manipulation.
        // Let's assume standard signatures:
        
        // However, a simpler heuristic for your case:
        // Identify if it is MICROSOFT (Safe-ish) or OTHERS (Bad).
        
        // Let's try a register scan helper approach or use the debug format hack
        let vendor_debug = format!("{:?}", hv); 
        
       // 1. ALLOWED HYPERVISORS (Windows Core Isolation / WSL2 / Docker)
        if vendor_debug.contains("Microsoft Hv") || vendor_debug.contains("HyperV") {
            return None; // Safe
        }

        // 2. BANNED HYPERVISORS (The Cheating Tools)
        if vendor_debug.contains("VMware") { 
            return Some("VMware Workstation/Player".to_string()); 
        }
        
        if vendor_debug.contains("VBox") || vendor_debug.contains("VirtualBox") { 
            return Some("Oracle VirtualBox".to_string()); 
        }
        
        if vendor_debug.contains("KVM") { 
            return Some("KVM (Linux Host)".to_string()); 
        }
        
        if vendor_debug.contains("Xen") { 
            return Some("Xen Hypervisor".to_string()); 
        }

        if vendor_debug.contains("Parallels") {
            return Some("Parallels Desktop".to_string());
        }

        // if it reaches here, it's a hypervisor that isn't Microsoft, Block it or Allow it
        return Some(format!("Unknown Hypervisor (Signature: {})", vendor_debug));
    }

    // fallback: if bit is set but no info
    None
}

// CLIPBOARD NUKE
// prevents copying code from a local text file to the browser
pub fn clear_clipboard() {
    unsafe {
        // tries to open clipboard (Window handle 0 = current task)
        if OpenClipboard(None).is_ok() {
            let _ = EmptyClipboard();
            let _ = CloseClipboard();
        }
    }
}

// returns a string of violations, or None if safe.
pub fn scan_environment() -> Option<String> {
    let checks = SecurityCheck::check();
    let mut violations: Vec<String> = Vec::new();

    if let Some(vendor) = checks.vm_vendor {
        // DEV MODE BYPASS LOGIC this is for testing only 
        if cfg!(debug_assertions) {
             println!("[DEBUG WARNING]: Virtual Machine detected ({}) - Ignored for Dev.", vendor);
        } else {
             violations.push(format!("[security]: VIRTUAL MACHINE DETECTED [{}]", vendor));
        }
    }

    if checks.is_remote {
        violations.push("[security]: REMOTE DESKTOP (RDP) DETECTED".to_string());
    }

    if checks.monitor_count > 1 {
        violations.push(format!("[security]: MULTIPLE MONITORS DETECTED ({})", checks.monitor_count));
    }

    if let Some(vpn_name) = checks.vpn_detected {
        violations.push(format!("[security]: VPN/PROXY DETECTED [{}]", vpn_name));
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations.join(" | "))
    }
}