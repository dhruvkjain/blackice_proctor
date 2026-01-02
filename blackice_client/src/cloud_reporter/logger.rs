use crate::network::WfpGuard;

#[derive(Debug, Clone)]
pub enum ViolationType {
    Application,
    Network,
    Environment,
    Other,
}

pub enum AppLogs {
    Info(String),
    Error(String),
    Violation(ViolationType, String),
    LockSuccess(WfpGuard),
    UnlockSuccess,
}