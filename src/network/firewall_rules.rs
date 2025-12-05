use std::net::ToSocketAddrs;
use windows::core::{BSTR, Result, HRESULT, Error};
use windows::Win32::System::Com::*;
use windows::Win32::NetworkManagement::WindowsFirewall::*;


const RULE_NAME: &str = "BlackICE_Firewall_TCP_Whitelist";
const DNS_RULE_NAME: &str = "BlackICE_Firewall_DNS_Whitelist";
const DHCP_RULE_NAME: &str = "BlackICE_Firewall_DHCP_Whitelist";

// dynamically converted to IPs
const WHITELIST_DOMAINS: &[&str] = &[
    // ------------ target sites
    "codeforces.com:443",
    "www.codeforces.com:443",
    "leetcode.com:443",
    "www.leetcode.com:443",

    // ------------ cloudflare security (codeforces uses it for auth)
    "challenges.cloudflare.com:443",

    // ------------ Google reCAPTCHA
    "www.google.com:443",
    "www.gstatic.com:443",
    "fonts.gstatic.com:443",
    "recaptcha.net:443",
    "www.recaptcha.net:443",

    // ------------ CDNs
    "cdnjs.cloudflare.com:443",
    "fonts.googleapis.com:443",
    "assets.leetcode.com:443",
];


// this function resolves IPs and applies the Block Policy
pub fn apply_rules() -> Result<String> {
    unsafe {
        // initialize COM library (VVIP for Windows APIs)
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    // ------------ Resolve Domains to IPs
    let mut ip_addresses = Vec::new();
    for domain in WHITELIST_DOMAINS {
        if let Ok(addrs) = domain.to_socket_addrs() {
            for addr in addrs {
                ip_addresses.push(addr.ip().to_string());
            }
        }
    }

    if ip_addresses.is_empty() {
        return Ok("[error]: Could not resolve any IPs (VPN might be active, check DNS?)".to_string());
    }

    let ip_list_str = ip_addresses.join(",");
    let count = ip_addresses.len();

    // ------------ Apply Windows Firewall Rules
    unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
        let rules: INetFwRules = policy.Rules()?;

        // clean up old rules first
        let _ = rules.Remove(&BSTR::from(RULE_NAME));
        let _ = rules.Remove(&BSTR::from(DNS_RULE_NAME));

        // Create Whitelist Rule (TCP)
        let new_rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_ALL)?;
        new_rule.SetName(&BSTR::from(RULE_NAME))?;
        new_rule.SetDescription(&BSTR::from("Allow access to whitelist domains"))?;
        new_rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
        new_rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
        new_rule.SetAction(NET_FW_ACTION_ALLOW)?;
        new_rule.SetEnabled(true.into())?;
        new_rule.SetRemoteAddresses(&BSTR::from(&ip_list_str))?;
        rules.Add(&new_rule)?;

        // Create DNS Rule (UDP 53)
        let dns_rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_ALL)?;
        dns_rule.SetName(&BSTR::from(DNS_RULE_NAME))?;
        dns_rule.SetProtocol(NET_FW_IP_PROTOCOL_UDP.0)?;
        dns_rule.SetRemotePorts(&BSTR::from("53"))?;
        dns_rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
        dns_rule.SetAction(NET_FW_ACTION_ALLOW)?;
        dns_rule.SetEnabled(true.into())?;
        rules.Add(&dns_rule)?;

        // DHCP Rule (IMP Wifi)
        let dhcp_rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_ALL)?;
        dhcp_rule.SetName(&BSTR::from(DHCP_RULE_NAME))?;
        dhcp_rule.SetDescription(&BSTR::from("Allow Wi-Fi negotiation"))?;
        dhcp_rule.SetProtocol(NET_FW_IP_PROTOCOL_UDP.0)?;
        dhcp_rule.SetLocalPorts(&BSTR::from("68"))?;  // client
        dhcp_rule.SetRemotePorts(&BSTR::from("67"))?; // server
        dhcp_rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
        dhcp_rule.SetAction(NET_FW_ACTION_ALLOW)?;
        dhcp_rule.SetEnabled(true.into())?;
        rules.Add(&dhcp_rule)?;

        // LOCK DOWN: Set Default Policy to BLOCK
        enable_strict_blocking(&policy)?;
    }

    Ok(format!("[network] [firewall rules] Secure Mode Active. Allowed {} IPs.", count))
}


// this function restores network access
pub fn reset_firewall() -> Result<String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
        let rules: INetFwRules = policy.Rules()?;

        // restore default policy to ALLOW
        policy.put_DefaultOutboundAction(NET_FW_PROFILE2_DOMAIN, NET_FW_ACTION_ALLOW)?;
        policy.put_DefaultOutboundAction(NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_ALLOW)?;
        policy.put_DefaultOutboundAction(NET_FW_PROFILE2_PUBLIC, NET_FW_ACTION_ALLOW)?;

        // remove our rules
        let _ = rules.Remove(&BSTR::from(RULE_NAME));
        let _ = rules.Remove(&BSTR::from(DNS_RULE_NAME));
        let _ = rules.Remove(&BSTR::from(DHCP_RULE_NAME));
    }
    
    Ok("Internet Restored. Default Policy: ALLOW.".to_string())
}


// VVIP this is called by the background thread to update IPs without breaking the connection
pub fn refresh_whitelist() -> Result<String> {
    unsafe { let _ = CoInitializeEx(None, COINIT_MULTITHREADED); }

    // resolve first, if DNS fails, we abort here so we don't break the firewall
    let ip_list_str = match resolve_all_domains() {
        Ok(s) => s,
        Err(e) => return Ok(format!("[network] [firewall rules] DNS Refresh Skipped: {}", e.message())),
    };

    unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
        let rules: INetFwRules = policy.Rules()?;

        // retrieve the existing rule rather than deleting it
        // this prevents "flickering" (momentary internet loss)
        match rules.Item(&BSTR::from(RULE_NAME)) {
            Ok(rule) => {
                // update the IPs on the live rule
                rule.SetRemoteAddresses(&BSTR::from(ip_list_str))?;
                Ok("[network] [firewall rules] Firewall Rules Updated (Dynamic DNS).".to_string())
            },
            Err(_) => {
                // if rule doesn't exist, re-apply everything
                apply_rules()
            }
        }
    }
}


// ------------ Helpers functions
fn resolve_all_domains() -> Result<String> {
    let mut ip_addresses = Vec::new();
    let mut resolved_count = 0;

    for domain in WHITELIST_DOMAINS {
        // use std::net logic, mapped to windows::core::Error if it fails completely
        if let Ok(addrs) = domain.to_socket_addrs() {
            for addr in addrs {
                ip_addresses.push(addr.ip().to_string());
            }
            resolved_count += 1;
        }
    }

    if ip_addresses.is_empty() {
        // return a Windows Error if resolution fails completely
        return Err(Error::new(HRESULT(0x80004005_u32 as i32), "DNS Resolution Failed"));
    }

    Ok(ip_addresses.join(","))
}


unsafe fn enable_strict_blocking(policy: &INetFwPolicy2) -> Result<()> {
    policy.put_DefaultOutboundAction(NET_FW_PROFILE2_DOMAIN, NET_FW_ACTION_BLOCK)?;
    policy.put_DefaultOutboundAction(NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_BLOCK)?;
    policy.put_DefaultOutboundAction(NET_FW_PROFILE2_PUBLIC, NET_FW_ACTION_BLOCK)?;
    Ok(())
}