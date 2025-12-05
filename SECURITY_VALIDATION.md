# Security Validation Doc

> **This Report was hand typed and emojis are intentional**
<br/>
This doc contains testing / working of BlackICE Proctor application

### Testing Environment:
- Application: [BlackICE Proctor](https://github.com/dhruvkjain/blackice_proctor)
- Date: December 2025
- Platform: Windows 10/11 x64
- Version: Release Build


<br/>
<br/>


## Test Case 1: Network Firewall Injection
**Objective**: Verify that the application successfully registers strict filtering rules with the Windows Kernel.
<p style='center'>
  <img width="1886" height="784" alt="1" src="https://github.com/user-attachments/assets/3947ccd0-610d-4cb3-94aa-9340e706d263" />
<p/>

**Observation**: The "Windows Defender Firewall with Advanced Security" console confirms the creation of three distinct outbound rules:
- `BlackICE_Firewall_DHCP_Whitelist`
- `BlackICE_Firewall_DNS_Whitelist`
- `BlackICE_Firewall_TCP_Whitelist`

**Logs**: `[network] [wfp]: NETWORK SECURED`

**Verdict**: ✅ The rules successfully override local network settings.


<br/>
<br/>
<br/>


## Test Case 2: Whitelist Verification and Background Process Monitoring
**Objective**: Confirm that `codeforces.com` is accessible while other websites are strictly blocked, also background processes are monitored.
<p style='center'>
  <img width="1482" height="784" alt="5" src="https://github.com/user-attachments/assets/949ca901-034e-4351-aa2c-c770fb3ecff9" />
<p/>
<p style='center'>
  <img width="1454" height="784" alt="6" src="https://github.com/user-attachments/assets/e2bd59c7-52d2-4eb7-bf98-0471a738543c" />
<p/>

**Observation**: 
- (first image) The Codeforces problem "Number Search!!!" loaded correctly with all **fonts and assets**.
- (second image) The attempt to load `youtube.com` was failed with error `ERR_NETWORK_ACCESS_DENIED` therefore browser displayed the standard "Your Internet access is blocked" error page.
- The application detected various developer tools running in the background, specifically:
    -  VS Code: `[security] SUSPICIOUS APP: 'code.exe'`
    -  Git Bash: `[security] SUSPICIOUS APP: 'bash.exe'`
    -  PowerToys: `[security] SUSPICIOUS APP: 'powertoys.exe'` (and associated utilities like `awake.exe`, `colorpickerui.exe`).

**Logs**: `[network] [firewall rules] Secure Mode Active. Allowed 22 IPs`

**Verdict**: ✅ Successfull attempt to navigate to a complex Codeforces problem page involving math formulas (requires CDN access) while other websites are blocked. 


<br/>
<br/>
<br/>


## Test Case 3: WFP Kernel level Network filtering
**Objective**: Ensure that request from processes / applications other than Google Chrome, Microsoft Edge and Firefoxto whitelisted domains are dropped.
<p style='center'>
  <img width="1470" height="784" alt="7" src="https://github.com/user-attachments/assets/fdf3b7b8-f39d-4c72-bb3e-301d01f5780e" />
<p/>

**Observation**: 
- The application detected that whitelisted domain i.e. `codeforces.com` was requested by Brave (tested with curl too) and was dropped with the error `ERR_NETWORK_ACCESS_DENIED`. 
- The browser displayed the standard "Your Internet access is blocked" error page.

**Verdict**: ✅ Application successfully detected a whitelisted domain request from unauthorized process and dropped it.

<br/>
<br/>
<br/>


## Test Case 4: Block Masquerade (renaming application) cheat
**Objective**: Detect any application that is running using name of whitelisted processes by checking it's path 
<p style='center'>
  <img width="1919" height="1025" alt="8" src="https://github.com/user-attachments/assets/e737b63d-b1ce-435a-8f1d-c3ec2d4d76ad" />
<p/>

**Observation**: Noita application was detected as Masquerade running under the name of whitelisted process `chrome.exe`.

**Verdict**: ✅ Application successfully detected a Masquerade attempt.


<br/>
<br/>
<br/>


## Test Case 5: VPN Evasion (ProtonVPN)
**Objective**: Verify resilience against Split Tunneling and Encrypted Tunneling attempts using Proton VPN.
1. **Scenario 1**: VPN Process Detection

   **Action**: Attempted to launch the ProtonVPN client GUI while the proctor app was running.
   <p style='center'>
     <img width="1589" height="784" alt="4" src="https://github.com/user-attachments/assets/e7a644af-f9be-4c5f-a0dd-59c2ab67874c" />
   </p>
   <p style='center'>
     <img width="1574" height="784" alt="3" src="https://github.com/user-attachments/assets/445b1224-9e7c-450c-934f-413ccb579bdb" />
   </p>
   
   **Observation**:
   - (first image) The Process Monitor immediately flagged the executable.
   - (second image) The Network Blocking would not allow to connect to VPN server as it is not in whitelist
     
   **Logs**: 
   - `[application] [security] SUSPICIOUS APP: 'protonvpn.client.exe'`
   - `[application] [security] BANNED WINDOW: 'proton vpn' (PID: 16740)`
   
   **Verdict**: ✅ Successfull detection of attempt to launch VPN while proctor application was running. 

<br/>
<br/>

2. **Scenario 2**: Tunneling Attempt (Fail-Secure)

    **Action**: The ProtonVPN, launched before starting proctor app, connected to a server in Romania (RO-FREE#24) to bypass the firewall rules.
   <p style='center'>
     <img width="1587" height="784" alt="2" src="https://github.com/user-attachments/assets/3ec08400-8760-481d-b505-8dd29785fecb" />
   </p>
   
   **Observation**: The Domain resolution for enforcing IP rule failed because the VPN's DNS server was not whitelisted.

   **Logs**: `[network] [firewall rules]: [error]: Could not resolve any IPs (VPN might be active, check DNS?)`

   **Verdict**: ✅ Successfull detection of attempt to launch VPN before proctor application is started. 
