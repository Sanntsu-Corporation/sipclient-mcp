package calltester

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emiago/sipgo"
)

func stubPESQScorer(t *testing.T) {
	t.Helper()
	scriptPath := filepath.Join(t.TempDir(), "fake_pesq.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nprintf '{\"pesq_raw\":4.20,\"mos_lqo\":4.20}\\n'\n"), 0o755); err != nil {
		t.Fatalf("write fake pesq scorer: %v", err)
	}
	t.Setenv(pesqPythonEnv, "/bin/sh")
	t.Setenv(pesqScorerScriptEnv, scriptPath)
}

// freeUDPAddr returns a concrete 127.0.0.1:<port> the kernel just confirmed is
// free, replacing the fixed 5080/5090/5190/5191 literals that collided under the
// loop gate's repeated runs. Concrete (not :0) because the self-test both binds
// and dials this address (sink.go). Test-only; G4 file-scope.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("allocate free udp port: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

func TestExecuteSelfTestOutboundPatterns(t *testing.T) {
	stubPESQScorer(t)

	store := NewStore(t.TempDir())

	regResult, err := Execute(context.Background(), store, TestRequest{
		TestCallID:          "CALL-P1",
		PatternKey:          "P1_REG_OUT",
		SampleCaller:        "0312345678",
		SampleCallee:        "05012345678",
		UserEndpointMode:    "register",
		CarrierEndpointMode: "ip2ip",
		CallScenario:        "outgoing",
		LocalAddr:           "127.0.0.1:0",
		ListenAddr:          freeUDPAddr(t),
		FromDomain:          "example.com",
		ToDomain:            "127.0.0.1",
		AuthUser:            "tester",
		AuthPass:            "pass",
		SelfTest:            true,
		AudioSource:         "sine:1000",
		RepeatRuns:          1,
		TimeoutMS:           4000,
		CallDurationMS:      1200,
	})
	if err != nil {
		t.Fatalf("register self-test failed: %v", err)
	}
	if regResult.Status != "SUCCESS" {
		t.Fatalf("expected success, got %s", regResult.Status)
	}
	if len(regResult.Runs) != 1 || regResult.Runs[0].RTPRXPackets == 0 {
		t.Fatalf("expected inbound RTP packets, got %+v", regResult.Runs)
	}
	if regResult.Runs[0].QualityMethod != "pesq_nb" || regResult.Runs[0].PESQMOSLQO != 4.2 {
		t.Fatalf("expected PESQ scorer output, got %+v", regResult.Runs[0])
	}

	time.Sleep(250 * time.Millisecond)

	ip2ipResult, err := Execute(context.Background(), store, TestRequest{
		TestCallID:          "CALL-P2",
		PatternKey:          "P2_IP2IP_OUT",
		SampleCaller:        "0312345678",
		SampleCallee:        "05012345678",
		UserEndpointMode:    "ip2ip",
		CarrierEndpointMode: "ip2ip",
		CallScenario:        "outgoing",
		LocalAddr:           "127.0.0.1:0",
		ListenAddr:          freeUDPAddr(t),
		FromDomain:          "example.com",
		ToDomain:            "127.0.0.1",
		SelfTest:            true,
		AudioSource:         "sine:1000",
		RepeatRuns:          1,
		TimeoutMS:           4000,
		CallDurationMS:      1200,
	})
	if err != nil {
		t.Fatalf("ip2ip self-test failed: %v", err)
	}
	if ip2ipResult.Status != "SUCCESS" {
		t.Fatalf("expected success, got %s", ip2ipResult.Status)
	}
	if len(ip2ipResult.Runs) != 1 || ip2ipResult.Runs[0].InviteFinalCode != 200 {
		t.Fatalf("expected successful invite, got %+v", ip2ipResult.Runs)
	}
}

func TestScorePESQNBUsesConfiguredScorer(t *testing.T) {
	stubPESQScorer(t)

	score, err := scorePESQNB([]byte{0xff, 0x7f, 0x00}, []byte{0xff, 0x7f, 0x00})
	if err != nil {
		t.Fatalf("scorePESQNB returned error: %v", err)
	}
	if score.Method != "pesq_nb" || score.RawScore != 4.2 || score.MOSLQO != 4.2 {
		t.Fatalf("unexpected score: %+v", score)
	}
}

func TestNormalizeRequestPreservesExplicitLocalAddr(t *testing.T) {
	req := normalizeRequest(TestRequest{
		PatternKey:          "P2_IP2IP_OUT",
		SampleCaller:        "0312345678",
		SampleCallee:        "05012345678",
		UserEndpointMode:    "ip2ip",
		CarrierEndpointMode: "ip2ip",
		CallScenario:        "outgoing",
		LocalAddr:           "192.168.11.10:5060",
		TargetURI:           "sip:05012345678@192.168.11.30:5061",
	})

	if req.LocalAddr != "192.168.11.10:5060" {
		t.Fatalf("expected explicit local addr to be preserved, got %s", req.LocalAddr)
	}
}

func TestNormalizeRequestPreservesDirectionAndCallerIdentityMode(t *testing.T) {
	req := normalizeRequest(TestRequest{
		PatternKey:          "P2_IP2IP_OUT",
		SampleCaller:        "0312345678",
		SampleCallee:        "05012345678",
		UserEndpointMode:    "ip2ip",
		CarrierEndpointMode: "ip2ip",
		CallScenario:        "incoming_anonymous",
		Direction:           "incoming",
		CallerIdentityMode:  "anonymous",
		LocalAddr:           "192.168.11.10:5060",
		TargetURI:           "sip:05012345678@192.168.11.30:5061",
	})

	if req.Direction != "incoming" {
		t.Fatalf("expected direction to be preserved, got %s", req.Direction)
	}
	if req.CallerIdentityMode != "anonymous" {
		t.Fatalf("expected caller identity mode to be preserved, got %s", req.CallerIdentityMode)
	}
}

func TestEndpointTypeForRequestPreservesExplicitLocalAddr(t *testing.T) {
	endpointType := endpointTypeForRequest(TestRequest{
		UserEndpointMode: "ip2ip",
		LocalAddr:        "192.168.8.244:5061",
	})

	if endpointType != "custom" {
		t.Fatalf("expected explicit local addr to force custom endpoint type, got %s", endpointType)
	}
}

func TestFinalizeResultCarriesDirectionAndCallerIdentityMode(t *testing.T) {
	startedAt := time.Now().UTC()
	endedAt := startedAt.Add(2 * time.Second)

	result := finalizeResult(
		TestRequest{
			TestCallID:          "CALL-P2",
			PatternKey:          "P2_IP2IP_OUT",
			SampleCaller:        "0312345678",
			SampleCallee:        "05012345678",
			UserEndpointMode:    "ip2ip",
			CarrierEndpointMode: "ip2ip",
			CallScenario:        "incoming_anonymous",
			Direction:           "incoming",
			CallerIdentityMode:  "anonymous",
		},
		startedAt,
		endedAt,
		[]RunResult{},
		"",
		"",
	)

	if result.Direction != "incoming" {
		t.Fatalf("expected direction to be carried into result, got %s", result.Direction)
	}
	if result.CallerIdentityMode != "anonymous" {
		t.Fatalf("expected caller identity mode to be carried into result, got %s", result.CallerIdentityMode)
	}
}

func TestExecuteInMemoryWithRuntimeReusesMediaSessionAcrossCalls(t *testing.T) {
	stubPESQScorer(t)

	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("create ua: %v", err)
	}
	runtime := NewRuntime(ua)
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Fatalf("close runtime: %v", err)
		}
		if err := ua.Close(); err != nil {
			t.Fatalf("close ua: %v", err)
		}
	})

	createdMediaSessions := 0
	originalMediaFactory := newMediaSessionFunc
	newMediaSessionFunc = func(localIP string) (*mediaSession, error) {
		createdMediaSessions++
		return originalMediaFactory(localIP)
	}
	t.Cleanup(func() {
		newMediaSessionFunc = originalMediaFactory
	})

	baseRequest := TestRequest{
		PatternKey:          "P2_IP2IP_OUT",
		SampleCaller:        "0312345678",
		SampleCallee:        "05012345678",
		UserEndpointMode:    "ip2ip",
		CarrierEndpointMode: "ip2ip",
		CallScenario:        "outgoing",
		LocalAddr:           "127.0.0.1:0",
		FromDomain:          "example.com",
		ToDomain:            "127.0.0.1",
		SelfTest:            true,
		AudioSource:         "sine:1000",
		RepeatRuns:          1,
		TimeoutMS:           4000,
		CallDurationMS:      1200,
	}

	firstResult, err := ExecuteInMemoryWithRuntime(context.Background(), runtime, TestRequest{
		TestCallID: "CALL-RUNTIME-1",
		ListenAddr: freeUDPAddr(t),
		TargetURI:  "",
		Metadata:   map[string]string{"case_id": "case-1"},
		PatternKey: baseRequest.PatternKey, SampleCaller: baseRequest.SampleCaller, SampleCallee: baseRequest.SampleCallee,
		UserEndpointMode: baseRequest.UserEndpointMode, CarrierEndpointMode: baseRequest.CarrierEndpointMode,
		CallScenario: baseRequest.CallScenario, LocalAddr: baseRequest.LocalAddr, FromDomain: baseRequest.FromDomain,
		ToDomain: baseRequest.ToDomain, SelfTest: baseRequest.SelfTest, AudioSource: baseRequest.AudioSource,
		RepeatRuns: baseRequest.RepeatRuns, TimeoutMS: baseRequest.TimeoutMS, CallDurationMS: baseRequest.CallDurationMS,
	})
	if err != nil {
		t.Fatalf("first execution failed: %v", err)
	}
	if firstResult.Status != "SUCCESS" {
		t.Fatalf("expected first success, got %+v", firstResult)
	}

	secondResult, err := ExecuteInMemoryWithRuntime(context.Background(), runtime, TestRequest{
		TestCallID: "CALL-RUNTIME-2",
		ListenAddr: freeUDPAddr(t),
		TargetURI:  "",
		Metadata:   map[string]string{"case_id": "case-2"},
		PatternKey: baseRequest.PatternKey, SampleCaller: baseRequest.SampleCaller, SampleCallee: baseRequest.SampleCallee,
		UserEndpointMode: baseRequest.UserEndpointMode, CarrierEndpointMode: baseRequest.CarrierEndpointMode,
		CallScenario: baseRequest.CallScenario, LocalAddr: baseRequest.LocalAddr, FromDomain: baseRequest.FromDomain,
		ToDomain: baseRequest.ToDomain, SelfTest: baseRequest.SelfTest, AudioSource: baseRequest.AudioSource,
		RepeatRuns: baseRequest.RepeatRuns, TimeoutMS: baseRequest.TimeoutMS, CallDurationMS: baseRequest.CallDurationMS,
	})
	if err != nil {
		t.Fatalf("second execution failed: %v", err)
	}
	if secondResult.Status != "SUCCESS" {
		t.Fatalf("expected second success, got %+v", secondResult)
	}
	if createdMediaSessions != 1 {
		t.Fatalf("expected one reusable media session, got %d", createdMediaSessions)
	}
}
