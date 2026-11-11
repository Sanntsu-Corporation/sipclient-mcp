package calltester

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/rtp"
)

const (
	packetInterval = 20 * time.Millisecond
	audioSamples   = 160
	codecPCMU      = "PCMU"
)

type mediaSession struct {
	conn      *net.UDPConn
	localIP   string
	localPort int
}

type mediaMetrics struct {
	txPackets      int
	rxPackets      int
	packetLoss     float64
	jitterAvgMS    float64
	jitterPeakMS   float64
	audioDuration  int64
	qualityR       float64
	pesqRaw        float64
	qualityMOS     float64
	qualityMethod  string
	qualityVerdict string
}

var newMediaSessionFunc = newMediaSession

func newMediaSession(localIP string) (*mediaSession, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(localIP, "0"))
	if err != nil {
		return nil, fmt.Errorf("resolve media addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen media: %w", err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	return &mediaSession{conn: conn, localIP: local.IP.String(), localPort: local.Port}, nil
}

func (m *mediaSession) Close() error {
	return m.conn.Close()
}

func (m *mediaSession) SDP() []byte {
	return []byte(fmt.Sprintf(
		"v=0\r\n"+
			"o=- 1 1 IN IP4 %s\r\n"+
			"s=cvs-call-tester\r\n"+
			"c=IN IP4 %s\r\n"+
			"t=0 0\r\n"+
			"m=audio %d RTP/AVP 0\r\n"+
			"a=rtpmap:0 PCMU/8000\r\n"+
			"a=sendrecv\r\n",
		m.localIP,
		m.localIP,
		m.localPort,
	))
}

func (m *mediaSession) Stream(ctx context.Context, remote *net.UDPAddr, duration time.Duration, audioSource string) (mediaMetrics, error) {
	if remote == nil {
		return mediaMetrics{}, fmt.Errorf("remote media addr is nil")
	}
	audioReader, err := NewAudioReader(audioSource)
	if err != nil {
		return mediaMetrics{}, fmt.Errorf("audio reader: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, duration+2*time.Second)
	defer cancel()

	startedAt := time.Now()
	var mu sync.Mutex
	var rxPackets int
	var expectedSeq uint16
	var haveSeq bool
	var lostPackets int
	var lastTransit float64
	var jitter float64
	var jitterPeak float64
	var firstRx time.Time
	var lastRx time.Time
	var receivedPayload []byte

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buffer := make([]byte, 1500)
		for {
			_ = m.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := m.conn.ReadFromUDP(buffer)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				return
			}
			now := time.Now()
			var pkt rtp.Packet
			if err := pkt.Unmarshal(buffer[:n]); err != nil {
				continue
			}
			transit := float64(now.Sub(startedAt).Milliseconds()) - float64(pkt.Timestamp)/8.0
			mu.Lock()
			rxPackets++
			if firstRx.IsZero() {
				firstRx = now
			}
			lastRx = now
			if haveSeq {
				if pkt.SequenceNumber > expectedSeq {
					lostPackets += int(pkt.SequenceNumber - expectedSeq)
				}
			} else {
				haveSeq = true
			}
			expectedSeq = pkt.SequenceNumber + 1
			if rxPackets > 1 {
				d := math.Abs(transit - lastTransit)
				jitter += (d - jitter) / 16.0
				if d > jitterPeak {
					jitterPeak = d
				}
			}
			lastTransit = transit
			receivedPayload = append(receivedPayload, pkt.Payload...)
			mu.Unlock()
		}
	}()

	ticker := time.NewTicker(packetInterval)
	defer ticker.Stop()
	sequence := uint16(rand.Uint32())
	timestamp := rand.Uint32()
	ssrc := rand.Uint32()
	txPackets := 0
	transmittedPayload := make([]byte, 0, int(duration/packetInterval)*audioSamples)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			payload := audioReader.ReadChunk(audioSamples)
			packet := &rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					PayloadType:    0,
					SequenceNumber: sequence,
					Timestamp:      timestamp,
					SSRC:           ssrc,
				},
				Payload: payload,
			}
			raw, err := packet.Marshal()
			if err != nil {
				return mediaMetrics{}, fmt.Errorf("marshal rtp: %w", err)
			}
			sent, err := sendRTP(func(b []byte) (int, error) { return m.conn.WriteToUDP(b, remote) }, raw)
			if err != nil {
				return mediaMetrics{}, fmt.Errorf("send rtp: %w", err)
			}
			if sent {
				txPackets++
				transmittedPayload = append(transmittedPayload, payload...)
			}
			sequence++
			timestamp += audioSamples
			if time.Since(startedAt) >= duration {
				break loop
			}
		}
	}

	cancel()
	<-recvDone

	mu.Lock()
	defer mu.Unlock()
	audioDuration := int64(0)
	if !firstRx.IsZero() && !lastRx.IsZero() && lastRx.After(firstRx) {
		audioDuration = lastRx.Sub(firstRx).Milliseconds() + packetInterval.Milliseconds()
	}
	if audioDuration == 0 && rxPackets > 0 {
		audioDuration = int64(rxPackets) * packetInterval.Milliseconds()
	}

	packetLossRatio := 1.0
	if total := rxPackets + lostPackets; total > 0 {
		packetLossRatio = float64(lostPackets) / float64(total)
	}
	if txPackets == 0 && rxPackets == 0 {
		packetLossRatio = 1.0
	}
	rValue := estimateR(packetLossRatio, jitter)
	pesqMethod := "pesq_nb"
	mos := 0.0
	pesqRaw := 0.0
	if len(transmittedPayload) > 0 && len(receivedPayload) > 0 {
		score, err := scorePESQNB(transmittedPayload, receivedPayload)
		if err != nil {
			return mediaMetrics{}, fmt.Errorf("score pesq: %w", err)
		}
		mos = score.MOSLQO
		pesqRaw = score.RawScore
		pesqMethod = score.Method
	}
	qualityVerdict := "fail"
	if rValue >= 70 && mos >= 3.2 {
		qualityVerdict = "pass"
	}

	return mediaMetrics{
		txPackets:      txPackets,
		rxPackets:      rxPackets,
		packetLoss:     packetLossRatio,
		jitterAvgMS:    jitter,
		jitterPeakMS:   jitterPeak,
		audioDuration:  audioDuration,
		qualityR:       rValue,
		pesqRaw:        pesqRaw,
		qualityMOS:     mos,
		qualityMethod:  pesqMethod,
		qualityVerdict: qualityVerdict,
	}, nil
}

// sendRTP writes one packet. A first packet that loses a conntrack race with the
// peer's own first packet fails with EPERM on kernels before 6.12 with a NAT
// table registered (CF-036): retry once, and if it fails again count it as a lost
// packet (sent=false, err=nil) rather than ending the stream. Other errors are
// returned unchanged.
func sendRTP(write func([]byte) (int, error), raw []byte) (sent bool, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = write(raw); err == nil {
			return true, nil
		}
		if !errors.Is(err, syscall.EPERM) {
			return false, err
		}
	}
	return false, nil
}

func parseRemoteMedia(body []byte, fallbackHost string) (*net.UDPAddr, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty sdp")
	}
	host := fallbackHost
	port := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "c=") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				host = fields[2]
			}
		}
		if strings.HasPrefix(line, "m=audio") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				parsed, err := strconv.Atoi(fields[1])
				if err != nil {
					return nil, fmt.Errorf("parse media port: %w", err)
				}
				port = parsed
			}
		}
	}
	if host == "" || port == 0 {
		return nil, fmt.Errorf("media address missing in sdp")
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func estimateR(packetLossRatio float64, jitterMS float64) float64 {
	lossPct := packetLossRatio * 100.0
	r := 93.2 - (lossPct * 25.0) - (jitterMS * 0.7)
	if r < 0 {
		return 0
	}
	if r > 100 {
		return 100
	}
	return r
}

func rToMOS(r float64) float64 {
	if r <= 0 {
		return 1.0
	}
	if r >= 100 {
		return 4.5
	}
	mos := 1.0 + 0.035*r + (7.0e-6 * r * (r - 60.0) * (100.0 - r))
	if mos < 1.0 {
		return 1.0
	}
	if mos > 4.5 {
		return 4.5
	}
	return mos
}
