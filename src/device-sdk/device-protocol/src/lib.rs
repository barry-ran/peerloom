/// 独占epoch跨JSON边界使用规范十进制字符串；不与协商代次混同。
pub fn parse_target_epoch(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 19
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|n| *n <= i64::MAX as u64)
}

/// Largest negotiation generation exactly representable by all JSON clients.
pub const MAX_NEGOTIATION_GENERATION: u64 = 9_007_199_254_740_991;

// Peerloom 传输无关的领域类型。

/// 连接路径策略；自动模式允许直接连接及 TURN 兜底。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPolicy {
    #[default]
    Auto,
    DirectOnly,
    RelayOnly,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMode {
    #[default]
    ReliableMessage,
    ReliableStream,
    LowLatencyMessage,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    #[default]
    Fail,
    DropOldest,
    DropNewest,
}

/// 路径与逻辑会话状态独立；未知不表示连接失败。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    #[default]
    Unknown,
    Direct,
    Relay,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    #[default]
    Requested,
    Authorizing,
    Connecting,
    Connected,
    Reconnecting,
    Closed,
}

impl SessionState {
    /// 只校验生命周期；不能替代服务端鉴权、目标确认和租约检查。
    /// 重复状态报告幂等；关闭为终态，不能因信令恢复自动复活。
    pub fn permits(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Requested, Self::Authorizing | Self::Closed)
                    | (Self::Authorizing, Self::Connecting | Self::Closed)
                    | (Self::Connecting, Self::Connected | Self::Closed)
                    | (Self::Connected, Self::Reconnecting | Self::Closed)
                    | (Self::Reconnecting, Self::Connected | Self::Closed)
            )
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorizing => "authorizing",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Closed => "closed",
        }
    }
}

/// 展示语言只影响文案，不改变稳定机器错误码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Chinese,
    English,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    AuthInvalid,
    DeviceRevoked,
    TenantForbidden,
    TargetOffline,
    TargetNotConnectable,
    GrantRequired,
    GrantExpired,
    TargetRejected,
    ConcurrencyLimit,
    RelayUnavailable,
    ProtocolUnsupported,
}

impl ErrorCode {
    pub const ALL: [Self; 11] = [
        Self::AuthInvalid,
        Self::DeviceRevoked,
        Self::TenantForbidden,
        Self::TargetOffline,
        Self::TargetNotConnectable,
        Self::GrantRequired,
        Self::GrantExpired,
        Self::TargetRejected,
        Self::ConcurrencyLimit,
        Self::RelayUnavailable,
        Self::ProtocolUnsupported,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthInvalid => "AUTH_INVALID",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::TenantForbidden => "TENANT_FORBIDDEN",
            Self::TargetOffline => "TARGET_OFFLINE",
            Self::TargetNotConnectable => "TARGET_NOT_CONNECTABLE",
            Self::GrantRequired => "GRANT_REQUIRED",
            Self::GrantExpired => "GRANT_EXPIRED",
            Self::TargetRejected => "TARGET_REJECTED",
            Self::ConcurrencyLimit => "CONCURRENCY_LIMIT",
            Self::RelayUnavailable => "RELAY_UNAVAILABLE",
            Self::ProtocolUnsupported => "PROTOCOL_UNSUPPORTED",
        }
    }

    pub const fn message(self, language: Language) -> &'static str {
        match (self, language) {
            (Self::AuthInvalid, Language::Chinese) => "认证无效",
            (Self::AuthInvalid, Language::English) => "Authentication is invalid",
            (Self::DeviceRevoked, Language::Chinese) => "设备已撤销",
            (Self::DeviceRevoked, Language::English) => "Device has been revoked",
            (Self::TenantForbidden, Language::Chinese) => "租户访问被拒绝",
            (Self::TenantForbidden, Language::English) => "Tenant access is forbidden",
            (Self::TargetOffline, Language::Chinese) => "目标设备离线",
            (Self::TargetOffline, Language::English) => "Target device is offline",
            (Self::TargetNotConnectable, Language::Chinese) => "目标设备不可连接",
            (Self::TargetNotConnectable, Language::English) => "Target is not connectable",
            (Self::GrantRequired, Language::Chinese) => "需要连接授权",
            (Self::GrantRequired, Language::English) => "Connection grant is required",
            (Self::GrantExpired, Language::Chinese) => "连接授权已过期",
            (Self::GrantExpired, Language::English) => "Connection grant has expired",
            (Self::TargetRejected, Language::Chinese) => "目标设备拒绝连接",
            (Self::TargetRejected, Language::English) => "Target rejected the connection",
            (Self::ConcurrencyLimit, Language::Chinese) => "已达到并发上限",
            (Self::ConcurrencyLimit, Language::English) => "Concurrency limit reached",
            (Self::RelayUnavailable, Language::Chinese) => "中继不可用",
            (Self::RelayUnavailable, Language::English) => "Relay is unavailable",
            (Self::ProtocolUnsupported, Language::Chinese) => "协议版本不受支持",
            (Self::ProtocolUnsupported, Language::English) => "Protocol is unsupported",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_matrix_and_terminal_state() {
        let states = [
            SessionState::Requested,
            SessionState::Authorizing,
            SessionState::Connecting,
            SessionState::Connected,
            SessionState::Reconnecting,
            SessionState::Closed,
        ];
        let expected = [
            [true, true, false, false, false, true],
            [false, true, true, false, false, true],
            [false, false, true, true, false, true],
            [false, false, false, true, true, true],
            [false, false, false, true, true, true],
            [false, false, false, false, false, true],
        ];
        for (i, state) in states.iter().enumerate() {
            for (j, next) in states.iter().enumerate() {
                assert_eq!(state.permits(*next), expected[i][j]);
            }
        }
    }

    #[test]
    fn machine_codes_unique_and_bilingual() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::ALL {
            assert!(seen.insert(code.as_str()));
            assert!(!code.message(Language::Chinese).is_empty());
            assert!(!code.message(Language::English).is_empty());
            assert_ne!(
                code.message(Language::Chinese),
                code.message(Language::English)
            );
        }
        assert_eq!(ErrorCode::AuthInvalid.as_str(), "AUTH_INVALID");
    }

    #[test]
    fn defaults_do_not_disable_transport_security() {
        assert_eq!(ConnectionPolicy::default(), ConnectionPolicy::Auto);
        assert_eq!(ChannelMode::default(), ChannelMode::ReliableMessage);
        assert_eq!(OverflowPolicy::default(), OverflowPolicy::Fail);
        assert_eq!(ConnectionPath::default(), ConnectionPath::Unknown);
        // 没有用于关闭 WebRTC DTLS 的配置字段。
    }
}
