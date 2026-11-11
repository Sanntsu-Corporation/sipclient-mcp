package calltester

import "time"

type TestRequest struct {
	TestCallID          string            `json:"test_call_id,omitempty"`
	PatternKey          string            `json:"pattern_key"`
	SampleCaller        string            `json:"sample_caller"`
	SampleCallee        string            `json:"sample_callee"`
	UserEndpointMode    string            `json:"user_endpoint_mode"`
	CarrierEndpointMode string            `json:"carrier_endpoint_mode"`
	CallScenario        string            `json:"call_scenario"`
	Direction           string            `json:"direction,omitempty"`
	CallerIdentityMode  string            `json:"caller_identity_mode,omitempty"`
	TargetURI           string            `json:"target_uri"`
	LocalAddr           string            `json:"local_addr"`
	ListenAddr          string            `json:"listen_addr,omitempty"`
	FromDomain          string            `json:"from_domain"`
	ToDomain            string            `json:"to_domain"`
	AuthUser            string            `json:"auth_user,omitempty"`
	AuthPass            string            `json:"auth_pass,omitempty"`
	Realm               string            `json:"realm,omitempty"`
	RepeatRuns          int               `json:"repeat_runs,omitempty"`
	TimeoutMS           int               `json:"timeout_ms,omitempty"`
	CallDurationMS      int               `json:"call_duration_ms,omitempty"`
	SelfTest            bool              `json:"self_test,omitempty"`
	AudioSource         string            `json:"audio_source,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

type TestStatus struct {
	TestCallID string     `json:"test_call_id"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at,omitempty"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	ErrorCode  string     `json:"error_code,omitempty"`
	Error      string     `json:"error,omitempty"`
	PatternKey string     `json:"pattern_key,omitempty"`
}

type RunResult struct {
	RunIndex          int      `json:"run_index"`
	CallID            string   `json:"call_id"`
	SIPCallID         string   `json:"sip_call_id"`
	Codec             string   `json:"codec"`
	SampleSetID       string   `json:"sample_set_id"`
	RTPTXPackets      int      `json:"rtp_tx_packets"`
	RTPRXPackets      int      `json:"rtp_rx_packets"`
	PacketLossRatio   float64  `json:"packet_loss_ratio"`
	JitterAvgMS       float64  `json:"jitter_avg_ms"`
	JitterPeakMS      float64  `json:"jitter_peak_ms"`
	AudioDurationMS   int64    `json:"audio_duration_ms"`
	RValue            float64  `json:"r_value"`
	PESQRaw           float64  `json:"pesq_raw"`
	PESQMOSLQO        float64  `json:"pesq_mos_lqo"`
	MOSJ              *float64 `json:"mos_j,omitempty"`
	TransportVerdict  string   `json:"transport_verdict"`
	QualityVerdict    string   `json:"quality_verdict"`
	OverallVerdict    string   `json:"overall_verdict"`
	FailureReason     *string  `json:"failure_reason"`
	InviteFinalCode   int      `json:"invite_final_code"`
	ByeFinalCode      int      `json:"bye_final_code"`
	RegisterFinalCode int      `json:"register_final_code,omitempty"`
	QualityMethod     string   `json:"quality_method"`
}

type AggregatedResult struct {
	TestCallID          string            `json:"test_call_id"`
	PatternKey          string            `json:"pattern_key"`
	UserEndpointMode    string            `json:"user_endpoint_mode"`
	CarrierEndpointMode string            `json:"carrier_endpoint_mode"`
	CallScenario        string            `json:"call_scenario"`
	Direction           string            `json:"direction,omitempty"`
	CallerIdentityMode  string            `json:"caller_identity_mode,omitempty"`
	Status              string            `json:"status"`
	StartedAt           time.Time         `json:"started_at"`
	EndedAt             time.Time         `json:"ended_at"`
	SIPCallID           string            `json:"sip_call_id"`
	CallID              string            `json:"call_id"`
	Codec               string            `json:"codec"`
	SampleSetID         string            `json:"sample_set_id"`
	Runs                []RunResult       `json:"runs"`
	AggregateRValue     float64           `json:"aggregate_r_value"`
	AggregatePESQMOSLQO float64           `json:"aggregate_pesq_mos_lqo"`
	TransportVerdict    string            `json:"transport_verdict"`
	QualityVerdict      string            `json:"quality_verdict"`
	OverallVerdict      string            `json:"overall_verdict"`
	CDRRequired         bool              `json:"cdr_required"`
	CDRScanStartFlowNo  *int64            `json:"cdr_scan_start_flowno,omitempty"`
	CDRScanLastFlowNo   *int64            `json:"cdr_scan_last_flowno,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	ErrorCode           string            `json:"error_code,omitempty"`
	Error               string            `json:"error,omitempty"`
}

type persistedState struct {
	Request TestRequest       `json:"request"`
	Status  TestStatus        `json:"status"`
	Result  *AggregatedResult `json:"result,omitempty"`
}
