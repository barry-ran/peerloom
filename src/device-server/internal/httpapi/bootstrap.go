package httpapi

// Bootstrap describes only implemented protocol capabilities, never tenant secrets.
// It is deliberately separate from readiness and does not promise a relay is deployed.
type Bootstrap struct {
	APIVersion          int      `json:"api_version"`
	SignalingPath       string   `json:"signaling_path"`
	RegistrationModes   []string `json:"registration_modes"`
	ChannelTypes        []string `json:"channel_types"`
	ManagedTURN         bool     `json:"managed_turn"`
	ApplicationE2EE     bool     `json:"application_e2ee"`
	WebRTCDTLSRequired  bool     `json:"webrtc_dtls_required"`
	MaxSignalFrameBytes int      `json:"max_signal_frame_bytes"`
	MaxMessageBytes     int      `json:"max_message_bytes"`
}

func capabilities() Bootstrap {
	return Bootstrap{APIVersion: 1, SignalingPath: "/v1/device-signal", RegistrationModes: []string{"grant"}, ChannelTypes: []string{"reliable_message", "low_latency_message"}, ManagedTURN: true, WebRTCDTLSRequired: true, MaxSignalFrameBytes: 128 << 10, MaxMessageBytes: 64 << 10}
}
