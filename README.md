> App is currently in construction.

<p align="center">
  <img width="246" height="237" alt="app_icon" src="https://github.com/user-attachments/assets/15699123-6664-49ce-9c9d-eb3fb2452633" />
</p>


<h1 align="center">BlackICE Proctor</h1>
<p align="center">
    <code>BlackICE</code>, a robust, system-level proctoring solution built in Rust designed to enforce strict testing environments by blocking unauthorized networks, applications, and hardware bypasses.
</p>

<br/>


Contents
========
- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Filesystem](#filesystem)
- [Installation and Usage](#installation-and-usage)
- [Running Application Images and Testing Report](https://github.com/dhruvkjain/blackice_proctor/blob/main/SECURITY_VALIDATION.md)

<br/>

> I have used LLMs help for improvements and boilerplate code

> While the Approach, Architecture and Logic was fully researched and developed by me

<br/>
<br/>

## Overview
BlackICE is a examination proctoring apppliaction written in pure Rust that uses `windows` crate APIs and modules isolate the user's environment to ensure academic integrity
- It allows only programming platforms like `codeforces.com` and `leetcode.com`
- It allows only Google Chrome, Microsoft Edge and Firefox for accessing the programming platforms
- It checks for blocking all other internet traffic, background applications, and virtualization tools
- **Note that it don't block applcation / processes and just log them currently for testing purposes**

<br/>
<br/>

## Tech Stack
 - Language: Rust
 - GUI : `egui` + `eframe` crate
 - System APIs: `windows` crate (Pure Win32 API interactions)
 - Low-Level Hardware: `raw-cpuid`crate (CPU feature flags & Hypervisor signatures)
 - Image Processing: `image` crate (Icon loading)

<br/>
<br/>

### Architecture
<p align="center">
  <img width="991" height="371" alt="image" src="https://github.com/user-attachments/assets/651fd495-74a7-4997-8269-3023b2fbafd3" />
<p/>


<br/>
<br/>


## Security Features
1. **Network Layer (Fail-Secure)**
   - **Kernel-Level Blocking (WFP):** Uses the Windows Filtering Platform API (`FwpmEngineOpen0`) to inject filters directly into the networking stack.
   - **Application Layer Enforcement (ALE) Lockdown:** Applies strict rules at the `FWPM_LAYER_ALE_AUTH_CONNECT_V4` layer to block all outbound TCP traffic by default.
   - **Application Whitelisting:** Uses `FwpmGetAppIdFromFileName0` to generate cryptographic IDs for allowed browsers (Chrome, Edge, Firefox) and system processes (svchost.exe), bypassing the block rule only for verified binaries.
   - **DNS Locking:** Prevents DNS resolution for unauthorized domains.

2. **Environment Integrity**
   - **VM Detection**: Checks CPUID leaves (`0x1`, `0x40000000`) for Hypervisor (Windows deafult for multiple Desktops) signatures. Detects VMware, VirtualBox, KVM, Xen, and Parallels.
   - **VPN/Proxy Detection**: Scans low-level **network adapters** using `GetAdaptersAddresses` (IP Helper API) to detect active VPN interfaces (TAP, TUN, WireGuard, NordLynx, etc.) and refuses startup.
   - **Virtual Desktop Detection**: Uses `IVirtualDesktopManager` to detect if the user switches to a hidden virtual desktop (Win + Ctrl + D) to bypass screen recording.
   - **RDP(Remote Desktop Protocol) & Multi-Monitor**: Blocks Remote Desktop Sessions (`SM_REMOTESESSION`) and Secondary Monitors (`SM_CMONITORS`).

3. Application Control
   - **Process Blocking**: Scans visible windows using `EnumWindows`. Filters out system background processes (`IsWindowVisible`) and kills unauthorized user applications.
   - **Clipboard Isolation**: Nukes the system clipboard to prevent copy-pasting code from external sources.


<br/>
<br/>


## Filesystem
```
📁 blackice_proctor/
├── Cargo.toml              # Dependencies and build configuration
└── 📁 src/
    ├── main.rs             # Entry point (Window setup)
    ├── lib.rs              # App state & Update loop
    ├── app_icon.png        # Embedded window icon
    ├── 📁 applications/       # Module: App blocking logic
    │   ├── mod.rs
    │   └── process_control.rs
    ├── 📁 network/            # Module: Network firewall logic
    │   ├── mod.rs
    │   ├── wfp.rs              # Low-level WFP API implementation
    │   └── firewall_rules.rs   # High-level DNS/Rule logic
    └── 📁 environment/        # Module: Anti-Cheat checks
        ├── mod.rs
        ├── bypass.rs       # High-level security checks (VM, RDP, Desktops)
        └── vpn.rs          # Low-level Windows API adapter scanning
```

<br/>
<br/>


## Installation and Usage

- **Prerequisites**
  - OS: Windows 10 or Windows 11 (Linux/macOS not supported due to Win32 API usage).
  - Rust: Stable Toolchain installed via rustup.
  - **Privileges: Must run as Administrator to modify firewall rules and query system metrics**.

- **Building**
  - Clone the repository
    ```bash
    git clone https://github.com/dhruvkjain/blackice_proctor
    cd proctor-dashboard
    ```
  - Build in Release mode (Optimized)
    ```bash
    cargo build --release
    ```

- **Running**
  - Right-click the generated binary (target/release/blackice_proctor.exe).
  - Select "Run as Administrator".
  - Note: If you run via terminal, ensure the terminal itself has Admin privileges.

<br/>
<br/>


## Future Improvements 

- **Cloud Reporting (MongoDB):** Integrate a MongoDB service in using it's Rust Driver to report violations, timestamps, and user sessions in real-time, allowing proctors to monitor students remotely.
- (VVIP) **Cryptographic App Verification:** Instead of blocking by name and path, block/allow applications by verifying the `SHA-256 hash` of the `executable binary`.
- **Webcam Monitoring:** Integrate `nokhwa` or `OpenCV` to capture periodic snapshots or detect user presence.
- **Dynamic Whitelisting:** Fetch the allowed URL/IP list from a secure server at runtime, rather than hardcoding it.
- **Driver-Level Blocking:** Move the network blocking logic from User Mode (WFP via API) to a Kernel Mode Driver for tamper-proof security.
