package config

import "time"

type Config struct {
	Mode      string // uac|uas|both
	Transport string // udp only
	Actor     ActorModeConfig

	// EndpointType controls local source-port policy for UAC flows:
	// - register: use random local UDP port
	// - ip2ip: use fixed local UDP port 5060
	// - custom: use LocalAddr as provided
	EndpointType string

	PersistentRegister bool // keep REGISTER endpoint online to receive incoming INVITE
	AutoAnswer         bool // keep local UAS active during UAC flow to answer loopback INVITEs

	ListenAddr string // UAS bind
	LocalAddr  string // actual local bind + Via/Contact source in UAC
	TargetURI  string // registrar/proxy or direct callee IP

	FromUser, FromDomain string
	ToUser, ToDomain     string

	DoRegister   bool
	DoCall       bool
	Timeout      time.Duration
	CallDuration time.Duration

	AuthUser    string
	AuthPass    string
	Realm       string
	AudioSource string
}

type ActorModeConfig struct {
	Enabled   bool
	ActorRole string
	Control   string
}
