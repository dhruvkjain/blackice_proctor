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
- **[Demo] Running Application Images and Testing:** [System Validation Report](https://github.com/dhruvkjain/blackice_proctor/blob/main/SECURITY_VALIDATION.md)

<br/>
<br/>

## Overview
BlackICE is a examination proctoring apppliaction written in pure Rust that uses `windows` crate APIs and modules isolate the user's environment to ensure academic integrity
- It allows only programming platforms like `codeforces.com` and `leetcode.com`
- It allows only Google Chrome, Microsoft Edge and Firefox for accessing the programming platforms
- It checks for blocking all other internet traffic, background applications, and virtualization tools
- It reports the violations to a Cloud Server that stores the reports in a Time-Series MongoDB instance 
- **Note that it don't block applcation / processes and just log them currently for testing purposes**

<br/>
<br/>

## Tech Stack
 - Language: Rust
 - GUI : `egui` + `eframe` crate
 - System APIs: `windows` crate (Pure Win32 API interactions)
 - Server: `axum` crate (uses `tower-http` and `tokio` crates)  
 - Low-Level Hardware: `raw-cpuid`crate (CPU feature flags & Hypervisor signatures)
 - Image Processing: `image` crate (Icon loading)

<br/>
<br/>

## Architecture
<p align="center">
  <img width="1121" height="1019" alt="image" src="https://github.com/user-attachments/assets/16c5ea9c-f0e8-4bbd-b780-dcd96fd4c24e" />
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

3. **Application Control**
   - **Process Blocking**: Scans visible windows using `EnumWindows`. Filters out system background processes (`IsWindowVisible`) and kills unauthorized user applications.
   - **Clipboard Isolation**: Nukes the system clipboard to prevent copy-pasting code from external sources.


<br/>
<br/>


## Filesystem
```
📁 blackice_proctor/
│
├── 📁 blackice_client/
│   ├── Cargo.toml
│   └── 📁 src/
│       ├── main.rs
│       ├── lib.rs
│       ├── app_icon.png
│       ├── 📁 applications/
│       │   ├── mod.rs
│       │   └── process_control.rs
│       ├── 📁 cloud_reporter/
│       │   ├── mod.rs
│       │   └── reporter.rs
│       ├── 📁 environment/
│       │   ├── mod.rs
│       │   ├── bypass.rs
│       │   └── vpn.rs
│       └── 📁 network/
│           ├── mod.rs
│           ├── wfp.rs
│           └── firewall_rules.rs   
│
└── 📁 blackice_server/
    ├── Cargo.toml
    ├── .env
    └── 📁 src/
        ├── main.rs
        ├── db.rs
        ├── handlers.rs
        └── models.rs
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
    cd blackice_proctor
    ```
  - Build Client in Release mode (Optimized)
    ```bash
    cd blackice_client
    cargo build --release
    ```
  - Build Server in Release mode (Optimized)
    ```bash
    cd ../blackice_server
    cargo build --release
    ```

- **Running**
  - Right-click the generated binary (target/release/blackice_server.exe) for server.
  - Right-click the generated binary (target/release/blackice_client.exe) for client-side desktop application.
  - Select "Run as Administrator".
  - Note: If you run via terminal, ensure the terminal itself has Admin privileges.

<br/>
<br/>


## Future Improvements 

- **Improve Cloud Reporting (MongoDB):** Integrate a MongoDB service in using it's Rust Driver to report violations, timestamps, and user sessions in real-time, allowing proctors to monitor students remotely.
- (VVIP) **Cryptographic App Verification:** Instead of blocking by name and path, block/allow applications by verifying the `SHA-256 hash` of the `executable binary`.
- **Webcam Monitoring:** Integrate `nokhwa` or `OpenCV` to capture periodic snapshots or detect user presence.
- **Dynamic Whitelisting:** Fetch the allowed URL/IP list from a secure server at runtime, rather than hardcoding it.
- **Driver-Level Blocking:** Move the network blocking logic from User Mode (WFP via API) to a Kernel Mode Driver for tamper-proof security.


<br/>
<br/>
<br/>

---
<sub>Built with 💻 & ☕️ | © 2025 [Dhruv Jain](https://github.com/dhruvkjain)</sub>
