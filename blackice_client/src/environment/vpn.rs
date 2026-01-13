use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::AF_UNSPEC;

pub fn scan_for_vpn() -> Option<String> {
    unsafe {
        // initial buffer size (15KB is recommended by Microsoft to avoid 2 calls)
        // read this: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
        let mut buf_len: u32 = 15000;
        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let mut ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        // first call to get the list (or the required size)
        let mut ret = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32, 
            GAA_FLAG_INCLUDE_PREFIX, 
            None, 
            Some(ptr), 
            &mut buf_len
        );

        // if buffer was too small, resize and try again
        if ret == ERROR_BUFFER_OVERFLOW.0 {
            buffer.resize(buf_len as usize, 0);
            ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            ret = GetAdaptersAddresses(
                AF_UNSPEC.0 as u32, 
                GAA_FLAG_INCLUDE_PREFIX, 
                None, 
                Some(ptr), 
                &mut buf_len
            );
        }

        if ret != NO_ERROR.0 && ret != ERROR_SUCCESS.0 {
            return None; // failed to get adapters
        }

        let mut current_adapter = ptr;
        while !current_adapter.is_null() {
            let adapter = &*current_adapter;

            if adapter.OperStatus == IfOperStatusUp {
                let friendly_name = adapter.FriendlyName.to_string().unwrap_or_default().to_lowercase();
                let desc = adapter.Description.to_string().unwrap_or_default().to_lowercase();

                // check blacklist
                let suspicious = vec![
                    "tap-windows", "vpn", "wireguard", "openvpn", "hamachi", 
                    "fortinet", "tun", "zerotier", "nordlynx", "proton", "windscribe"
                ];

                for keyword in suspicious {
                    if friendly_name.contains(keyword) || desc.contains(keyword) {
                        return Some(format!("VPN Detected: {} ({})", friendly_name, desc));
                    }
                }
            }

            current_adapter = adapter.Next;
        }
    }
    None
}