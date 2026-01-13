use std::ffi::c_void;
use std::mem::zeroed;
use std::path::Path;
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;


const PROCTOR_PROVIDER_KEY: GUID = GUID::from_u128(0x4B6E8F31_2C5A_4B9A_9F0A_1B2C3D4E5F6A);
const PROCTOR_SUBLAYER_KEY: GUID = GUID::from_u128(0x8A1B2C3D_4E5F_6A7B_8C9D_0E1F2A3B4C5D);

// if these files does not exist then WFP will fail to generate an App ID
const ALLOWED_APPS_EXACT: &[&str] = &[
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    // DEBUG: for mongodb connection add some logic to allow this app
    // r"C:\Users\YourName\...\traffic_control.exe"
    
    // system processes needed for Wifi/DNS
    r"C:\Windows\System32\svchost.exe", 
    r"C:\Windows\System32\lsass.exe",
];


pub struct WfpGuard {
    engine_handle: HANDLE,
}

unsafe impl Send for WfpGuard {}

impl WfpGuard {
    pub fn new() -> Result<Self, String> {
        unsafe {
            let mut handle = HANDLE::default();
            
            // Open WFP Engine Session
            let mut session: FWPM_SESSION0 = zeroed();
             // removes filters automatically if our app crashes/closes
            session.flags = FWPM_SESSION_FLAG_DYNAMIC; 

            let err = FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut handle,
            );

            if err != ERROR_SUCCESS.0 {
                return Err(format!("[wfp]: Failed to open WFP Engine: Code {}", err));
            }

            Ok(Self { engine_handle: handle })
        }
    }

    pub fn apply_ale_lockdown(&self) -> Result<(), String> {
        unsafe {
            // atart transaction
            let err = FwpmTransactionBegin0(self.engine_handle, 0);
            if err != ERROR_SUCCESS.0 { return Err("[wfp]: Transaction Begin Failed".into()); }

            // register provider
            let mut provider: FWPM_PROVIDER0 = zeroed();
            provider.providerKey = PROCTOR_PROVIDER_KEY;
            provider.displayData.name = wstr("BlackICE Proctor Provider");
            
            let _ = FwpmProviderAdd0(self.engine_handle, &provider, None);

            // creating sublayer
            let mut sublayer: FWPM_SUBLAYER0 = zeroed();
            sublayer.subLayerKey = PROCTOR_SUBLAYER_KEY;
            sublayer.displayData.name = wstr("BlackICE Proctor Lock Layer");
            sublayer.providerKey = &PROCTOR_PROVIDER_KEY as *const GUID as *mut GUID;
            // max weight to override others
            sublayer.weight = 0xFFFF;
            
            let _ = FwpmSubLayerAdd0(self.engine_handle, &sublayer, None);

            // block all IPv4 'Outbound' TCP traffic at the 'ALE' layer.
            self.add_filter(
                "Block All Outbound",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_BLOCK,
                1,
                None
            )?;

            // permit whitelist filter
            for (i, app_path) in ALLOWED_APPS_EXACT.iter().enumerate() {
                if !Path::new(app_path).exists() {
                    println!("Skipping missing app: {}", app_path);
                    continue; 
                }

                let mut app_id_blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                let err = FwpmGetAppIdFromFileName0(wstr(app_path), &mut app_id_blob);
                
                if err == ERROR_SUCCESS.0 && !app_id_blob.is_null() {
                    let mut condition: FWPM_FILTER_CONDITION0 = zeroed();
                    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID; 
                    condition.matchType = FWP_MATCH_EQUAL;
                    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    condition.conditionValue.Anonymous.byteBlob = app_id_blob;

                    let filter_name = format!("Permit App {}", i);

                    let res = self.add_filter(
                        &filter_name,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FWP_ACTION_PERMIT,
                        15,
                        Some(&[condition])
                    );

                    // free the memory Windows allocated for the ID
                    FwpmFreeMemory0(&mut app_id_blob as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void);

                    if let Err(e) = res {
                        println!("Failed to whitelist {}: {}", app_path, e);
                    }
                } else {
                    println!("Could not generate App ID for {}. Code: {}", app_path, err);
                }
            }

            let err = FwpmTransactionCommit0(self.engine_handle);
            if err != ERROR_SUCCESS.0 { return Err("[wfp]: WFP Commit Failed".into()); }

            Ok(())
        }
    }

    unsafe fn add_filter(
        &self,
        name: &str,
        layer_key: GUID,
        action_type: FWP_ACTION_TYPE,
        weight_uint8: u8,
        conditions: Option<&[FWPM_FILTER_CONDITION0]>,
    ) -> Result<(), String> {
        let mut filter: FWPM_FILTER0 = zeroed();
        filter.filterKey = GUID::new().unwrap();
        filter.providerKey = &PROCTOR_PROVIDER_KEY as *const GUID as *mut GUID;
        filter.subLayerKey = PROCTOR_SUBLAYER_KEY;
        filter.layerKey = layer_key;
        filter.displayData.name = wstr(name);
        
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = weight_uint8;

        filter.action.r#type = action_type;

        if let Some(conds) = conditions {
            filter.numFilterConditions = conds.len() as u32;
            filter.filterCondition = conds.as_ptr() as *mut _;
        }

        let err = FwpmFilterAdd0(self.engine_handle, &filter, None, None);
        if err != ERROR_SUCCESS.0 {
            return Err(format!("[wfp] Failed to add filter '{}': {}", name, err));
        }
        Ok(())
    }
}

impl Drop for WfpGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.engine_handle);
        }
    }
}

// Helper functions

// wide strings (Windows uses UTF-16)
fn wstr(s: &str) -> PWSTR {
    let encoded: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    
    let boxed = encoded.into_boxed_slice();
    let ptr = Box::leak(boxed).as_mut_ptr(); 
    PWSTR(ptr)
}