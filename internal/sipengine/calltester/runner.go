package calltester

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/config"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/digest"
	"github.com/sanntsu-corporation/sipclient-mcp/internal/sipengine/siptest"
)

type Runtime struct {
	ua *sipgo.UserAgent

	mu          sync.Mutex
	mediaByHost map[string]*mediaSession
}

func NewRuntime(ua *sipgo.UserAgent) *Runtime {
	return &Runtime{ua: ua}
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for host, media := range r.mediaByHost {
		if media == nil {
			continue
		}
		if err := media.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("close media session %s: %w", host, err))
		}
	}
	r.mediaByHost = nil
	return errors.Join(errs...)
}

func (r *Runtime) userAgent() *sipgo.UserAgent {
	if r == nil {
		return nil
	}
	return r.ua
}

func (r *Runtime) mediaSession(localIP string) (*mediaSession, bool, error) {
	if r == nil {
		media, err := newMediaSessionFunc(localIP)
		if err != nil {
			return nil, false, err
		}
		return media, true, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if media, ok := r.mediaByHost[localIP]; ok && media != nil {
		return media, false, nil
	}
	media, err := newMediaSessionFunc(localIP)
	if err != nil {
		return nil, false, err
	}
	if r.mediaByHost == nil {
		r.mediaByHost = make(map[string]*mediaSession)
	}
	r.mediaByHost[localIP] = media
	return media, false, nil
}

func Execute(ctx context.Context, store *Store, request TestRequest) (AggregatedResult, error) {
	normalized := normalizeRequest(request)
	now := time.Now().UTC()
	initial := persistedState{
		Request: normalized,
		Status: TestStatus{
			TestCallID: normalized.TestCallID,
			Status:     "RUNNING",
			StartedAt:  now,
			PatternKey: normalized.PatternKey,
		},
	}
	if err := store.Write(initial); err != nil {
		return AggregatedResult{}, err
	}

	result, err := runScenario(ctx, normalized)
	finishedAt := time.Now().UTC()
	if err != nil {
		status := initial.Status
		status.Status = "FAIL"
		status.EndedAt = &finishedAt
		status.ErrorCode = classifyError(err)
		status.Error = err.Error()
		_ = store.Write(persistedState{Request: normalized, Status: status})
		return AggregatedResult{}, err
	}

	status := TestStatus{
		TestCallID: normalized.TestCallID,
		Status:     result.Status,
		StartedAt:  result.StartedAt,
		EndedAt:    &result.EndedAt,
		PatternKey: normalized.PatternKey,
	}
	if err := store.Write(persistedState{Request: normalized, Status: status, Result: &result}); err != nil {
		return AggregatedResult{}, err
	}
	return result, nil
}

func ExecuteInMemory(ctx context.Context, request TestRequest) (AggregatedResult, error) {
	return ExecuteInMemoryWithUA(ctx, nil, request)
}

func ExecuteInMemoryWithUA(ctx context.Context, ua *sipgo.UserAgent, request TestRequest) (AggregatedResult, error) {
	runtime := NewRuntime(ua)
	defer runtime.Close()
	return ExecuteInMemoryWithRuntime(ctx, runtime, request)
}

func ExecuteInMemoryWithRuntime(ctx context.Context, runtime *Runtime, request TestRequest) (AggregatedResult, error) {
	normalized := normalizeRequest(request)
	return runScenarioWithRuntime(ctx, normalized, runtime)
}

func normalizeRequest(request TestRequest) TestRequest {
	if request.TestCallID == "" {
		request.TestCallID = fmt.Sprintf("CALL-%d", time.Now().UTC().UnixNano())
	}
	if request.RepeatRuns <= 0 {
		request.RepeatRuns = 3
	}
	if request.TimeoutMS <= 0 {
		request.TimeoutMS = 8000
	}
	if request.CallDurationMS <= 0 {
		request.CallDurationMS = 10_000
	}
	if request.Realm == "" {
		request.Realm = "siptester"
	}
	if request.UserEndpointMode == "register" {
		request.ListenAddr = defaultIfEmpty(request.ListenAddr, "127.0.0.1:5060")
	}
	return request
}

func runScenario(ctx context.Context, request TestRequest) (AggregatedResult, error) {
	return runScenarioWithRuntime(ctx, request, nil)
}

func runScenarioWithRuntime(ctx context.Context, request TestRequest, runtime *Runtime) (AggregatedResult, error) {
	runs := make([]RunResult, 0, request.RepeatRuns)
	startedAt := time.Now().UTC()
	for runIndex := 1; runIndex <= request.RepeatRuns; runIndex++ {
		run, err := executeRun(ctx, request, runIndex, runtime)
		if err != nil {
			failure := err.Error()
			run.FailureReason = &failure
			run.OverallVerdict = "fail"
			run.TransportVerdict = "fail"
			run.QualityVerdict = "fail"
			runs = append(runs, run)
			return finalizeResult(request, startedAt, time.Now().UTC(), runs, classifyError(err), err.Error()), nil
		}
		runs = append(runs, run)
	}
	return finalizeResult(request, startedAt, time.Now().UTC(), runs, "", ""), nil
}

func executeRun(ctx context.Context, request TestRequest, runIndex int, runtime *Runtime) (RunResult, error) {
	cfg := config.Config{
		Mode:               "uac",
		Transport:          "udp",
		EndpointType:       endpointTypeForRequest(request),
		LocalAddr:          request.LocalAddr,
		TargetURI:          request.TargetURI,
		FromUser:           request.SampleCaller,
		FromDomain:         request.FromDomain,
		ToUser:             request.SampleCallee,
		ToDomain:           request.ToDomain,
		DoRegister:         request.UserEndpointMode == "register",
		DoCall:             true,
		Timeout:            time.Duration(request.TimeoutMS) * time.Millisecond,
		CallDuration:       time.Duration(request.CallDurationMS) * time.Millisecond,
		AuthUser:           request.AuthUser,
		AuthPass:           request.AuthPass,
		Realm:              request.Realm,
		PersistentRegister: false,
		AutoAnswer:         false,
		AudioSource:        request.AudioSource,
	}
	if err := config.ApplyLocalPolicy(&cfg); err != nil {
		return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if request.SelfTest {
		if request.TargetURI == "" {
			cfg.TargetURI = normalizeTargetURI(request.ListenAddr)
		}
		serverDone, err := startLoopbackUAS(runCtx, cfg, request.ListenAddr)
		if err != nil {
			return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, err
		}
		defer func() {
			cancel()
			<-serverDone
		}()
		time.Sleep(200 * time.Millisecond)
	}

	ua := runtime.userAgent()
	ownedUA := false
	if ua == nil {
		var err error
		ua, err = sipgo.NewUA()
		if err != nil {
			return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, fmt.Errorf("create ua: %w", err)
		}
		ownedUA = true
	}
	if ownedUA {
		defer ua.Close()
	}

	client, err := siptest.NewClient(cfg, ua)
	if err != nil {
		return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, fmt.Errorf("create client: %w", err)
	}
	defer client.Close()

	registerCode := 0
	if cfg.DoRegister {
		registerRequest := siptest.BuildRegister(cfg, "udp")
		registerResponse, err := client.DoRequestWithDigest(runCtx, registerRequest)
		if err != nil {
			return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, fmt.Errorf("register: %w", err)
		}
		registerCode = int(registerResponse.StatusCode)
		if registerCode != 200 {
			return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, fmt.Errorf("register failed: %d", registerCode)
		}
	}

	localHost, _, _ := net.SplitHostPort(cfg.LocalAddr)
	media, closeMedia, err := runtime.mediaSession(localHost)
	if err != nil {
		return RunResult{RunIndex: runIndex, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, err
	}
	if closeMedia {
		defer media.Close()
	}

	inviteRequest := siptest.BuildInvite(cfg, "udp", media.SDP())
	callID := ""
	if header := inviteRequest.CallID(); header != nil {
		callID = header.Value()
	}
	inviteResponse, err := client.DoRequestWithDigest(runCtx, inviteRequest)
	if err != nil {
		return RunResult{RunIndex: runIndex, CallID: callID, SIPCallID: callID, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate"}, fmt.Errorf("invite: %w", err)
	}
	if inviteResponse.StatusCode < 200 || inviteResponse.StatusCode >= 300 {
		return RunResult{RunIndex: runIndex, CallID: callID, SIPCallID: callID, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate", InviteFinalCode: int(inviteResponse.StatusCode)}, fmt.Errorf("invite failed: %d", inviteResponse.StatusCode)
	}

	remoteHost := cfg.ToDomain
	if parsed, ok := parseTargetHost(cfg.TargetURI); ok {
		remoteHost = parsed
	}
	remoteMedia, err := parseRemoteMedia(inviteResponse.Body(), remoteHost)
	if err != nil {
		return RunResult{RunIndex: runIndex, CallID: callID, SIPCallID: callID, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate", InviteFinalCode: int(inviteResponse.StatusCode)}, err
	}

	ack := sip.NewAckRequest(inviteRequest, inviteResponse, nil)
	if err := client.Raw().WriteRequest(ack); err != nil {
		return RunResult{RunIndex: runIndex, CallID: callID, SIPCallID: callID, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate", InviteFinalCode: int(inviteResponse.StatusCode)}, fmt.Errorf("ack: %w", err)
	}

	metrics, err := media.Stream(runCtx, remoteMedia, cfg.CallDuration, cfg.AudioSource)
	if err != nil {
		return RunResult{RunIndex: runIndex, CallID: callID, SIPCallID: callID, Codec: codecPCMU, SampleSetID: "synthetic-pcmu-silence-v1", QualityMethod: "r_factor_estimate", InviteFinalCode: int(inviteResponse.StatusCode)}, err
	}

	bye := siptest.BuildByeFromInvite(inviteRequest, inviteResponse)
	byeResponse, err := client.RawTransaction(runCtx, bye, cfg.Timeout)
	if err != nil {
		return buildRunResult(runIndex, callID, registerCode, int(inviteResponse.StatusCode), 0, metrics), fmt.Errorf("bye: %w", err)
	}
	result := buildRunResult(runIndex, callID, registerCode, int(inviteResponse.StatusCode), int(byeResponse.StatusCode), metrics)
	if byeResponse.StatusCode != 200 {
		return result, fmt.Errorf("bye failed: %d", byeResponse.StatusCode)
	}
	if result.RTPRXPackets == 0 {
		return result, errors.New("RTP_NOT_DETECTED")
	}
	return result, nil
}

func endpointTypeForRequest(request TestRequest) string {
	if strings.TrimSpace(request.LocalAddr) != "" {
		return "custom"
	}
	return request.UserEndpointMode
}

func buildRunResult(runIndex int, callID string, registerCode int, inviteCode int, byeCode int, metrics mediaMetrics) RunResult {
	transportVerdict := "fail"
	if metrics.packetLoss <= 0.01 && metrics.jitterAvgMS <= 20 && metrics.jitterPeakMS <= 30 && metrics.rxPackets > 0 {
		transportVerdict = "pass"
	}
	overallVerdict := "fail"
	if transportVerdict == "pass" && metrics.qualityVerdict == "pass" {
		overallVerdict = "pass"
	}
	return RunResult{
		RunIndex:          runIndex,
		CallID:            callID,
		SIPCallID:         callID,
		Codec:             codecPCMU,
		SampleSetID:       "synthetic-pcmu-silence-v1",
		RTPTXPackets:      metrics.txPackets,
		RTPRXPackets:      metrics.rxPackets,
		PacketLossRatio:   metrics.packetLoss,
		JitterAvgMS:       metrics.jitterAvgMS,
		JitterPeakMS:      metrics.jitterPeakMS,
		AudioDurationMS:   metrics.audioDuration,
		RValue:            metrics.qualityR,
		PESQRaw:           metrics.pesqRaw,
		PESQMOSLQO:        metrics.qualityMOS,
		TransportVerdict:  transportVerdict,
		QualityVerdict:    metrics.qualityVerdict,
		OverallVerdict:    overallVerdict,
		InviteFinalCode:   inviteCode,
		ByeFinalCode:      byeCode,
		RegisterFinalCode: registerCode,
		QualityMethod:     metrics.qualityMethod,
	}
}

func finalizeResult(request TestRequest, startedAt, endedAt time.Time, runs []RunResult, errorCode string, errMsg string) AggregatedResult {
	aggregateR := 0.0
	aggregateMOS := 0.0
	transportVerdict := "pass"
	qualityVerdict := "pass"
	overallVerdict := "pass"
	for i := range runs {
		aggregateR += runs[i].RValue
		aggregateMOS += runs[i].PESQMOSLQO
		if runs[i].TransportVerdict != "pass" {
			transportVerdict = "fail"
		}
		if runs[i].QualityVerdict != "pass" {
			qualityVerdict = "fail"
		}
		if runs[i].OverallVerdict != "pass" {
			overallVerdict = "fail"
		}
	}
	if len(runs) > 0 {
		aggregateR /= float64(len(runs))
		aggregateMOS /= float64(len(runs))
	}
	status := "SUCCESS"
	if overallVerdict != "pass" {
		status = "FAIL"
	}
	if errorCode != "" {
		status = "FAIL"
	}
	callID := ""
	if len(runs) > 0 {
		callID = runs[len(runs)-1].CallID
	}
	return AggregatedResult{
		TestCallID:          request.TestCallID,
		PatternKey:          request.PatternKey,
		UserEndpointMode:    request.UserEndpointMode,
		CarrierEndpointMode: request.CarrierEndpointMode,
		CallScenario:        request.CallScenario,
		Direction:           request.Direction,
		CallerIdentityMode:  request.CallerIdentityMode,
		Status:              status,
		StartedAt:           startedAt,
		EndedAt:             endedAt,
		SIPCallID:           callID,
		CallID:              callID,
		Codec:               codecPCMU,
		SampleSetID:         "synthetic-pcmu-silence-v1",
		Runs:                runs,
		AggregateRValue:     aggregateR,
		AggregatePESQMOSLQO: aggregateMOS,
		TransportVerdict:    transportVerdict,
		QualityVerdict:      qualityVerdict,
		OverallVerdict:      overallVerdict,
		CDRRequired:         true,
		Metadata:            request.Metadata,
		ErrorCode:           errorCode,
		Error:               errMsg,
	}
}

func classifyError(err error) string {
	message := strings.ToUpper(err.Error())
	switch {
	case strings.Contains(message, "RTP_NOT_DETECTED"):
		return "RTP_NOT_DETECTED"
	case strings.Contains(message, "REGISTER"):
		return "AUTH_FAILED"
	case strings.Contains(message, "INVITE"):
		return "SIP_UNEXPECTED_FINAL"
	default:
		return "SYSTEM_EXCEPTION"
	}
}

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func normalizeTargetURI(listenAddr string) string {
	return "sip:" + listenAddr
}

func parseTargetHost(target string) (string, bool) {
	normalized := target
	if !strings.HasPrefix(strings.ToLower(normalized), "sip:") {
		normalized = "sip:" + normalized
	}
	var uri sip.Uri
	if err := sip.ParseUri(normalized, &uri); err != nil {
		return "", false
	}
	return uri.Host, uri.Host != ""
}

func startLoopbackUAS(ctx context.Context, cfg config.Config, listenAddr string) (<-chan struct{}, error) {
	ua, err := sipgo.NewUA()
	if err != nil {
		return nil, fmt.Errorf("create loopback ua: %w", err)
	}
	server, err := sipgo.NewServer(ua)
	if err != nil {
		ua.Close()
		return nil, fmt.Errorf("create loopback server: %w", err)
	}
	done := make(chan struct{})
	nonce := "cvstest-loopback"

	server.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		if !loopbackAuthOK(cfg, nonce, req) {
			_ = tx.Respond(loopbackChallenge(cfg, nonce, req))
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	server.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		if !loopbackAuthOK(cfg, nonce, req) {
			_ = tx.Respond(loopbackChallenge(cfg, nonce, req))
			return
		}
		offerHost, _, _ := net.SplitHostPort(listenAddr)
		remoteMedia, err := parseRemoteMedia(req.Body(), offerHost)
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		media, err := newMediaSession(offerHost)
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Media Failure", nil))
			return
		}

		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		ok := sip.NewSDPResponseFromRequest(req, media.SDP())
		_ = tx.Respond(ok)
		go func() {
			defer media.Close()
			_, _ = media.Stream(ctx, remoteMedia, cfg.CallDuration, cfg.AudioSource)
		}()
	})

	server.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		// ACK for 2xx INVITE is non-transactional; accept it explicitly to avoid 405.
	})

	server.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	go func() {
		defer close(done)
		defer server.Close()
		defer ua.Close()
		_ = server.ListenAndServe(ctx, "udp", listenAddr)
	}()
	return done, nil
}

func loopbackChallenge(cfg config.Config, nonce string, req *sip.Request) *sip.Response {
	realm := cfg.Realm
	if realm == "" {
		realm = "siptester"
	}
	response := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
	header := `Digest realm="` + realm + `", nonce="` + nonce + `", algorithm=MD5, qop="auth"`
	response.AppendHeader(sip.NewHeader("WWW-Authenticate", header))
	return response
}

func loopbackAuthOK(cfg config.Config, nonce string, req *sip.Request) bool {
	if cfg.AuthUser == "" || cfg.AuthPass == "" {
		return true
	}
	header := req.GetHeader("Authorization")
	if header == nil {
		return false
	}
	fields, err := digest.ParseAuthorization(header.Value())
	if err != nil {
		return false
	}
	if fields["username"] != cfg.AuthUser || fields["nonce"] != nonce {
		return false
	}
	return digest.VerifyMD5Auth(cfg.AuthUser, cfg.AuthPass, string(req.Method), fields)
}
