package media

import (
	"reflect"
	"testing"
)

func TestNoCommonCodecDetail(t *testing.T) {
	e := NoCommonCodec([]string{"PCMA"}, []string{"PCMU"})
	want := map[string]any{
		"kind":              "no_common_codec",
		"offered":           []string{"PCMA"},
		"acceptable":        []string{"PCMU"},
		"sip_response_sent": 488,
	}
	if got := e.Detail(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Detail()=%#v want %#v", got, want)
	}
	if e.Error() == "" {
		t.Fatal("Error() must be non-empty")
	}
}

func TestSRTPPeerOfferedAVPDetail(t *testing.T) {
	e := SRTPPeerOfferedAVP(SRTPRequired, "RTP/AVP")
	want := map[string]any{
		"kind":              "srtp_required_but_peer_offered_avp",
		"offered_profile":   "RTP/AVP",
		"required_profile":  "RTP/SAVP",
		"sip_response_sent": 488,
	}
	if got := e.Detail(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Detail()=%#v want %#v", got, want)
	}
}

func TestAnswerCodecNotOfferedDetail(t *testing.T) {
	e := AnswerCodecNotOffered([]string{"PCMU"}, []string{"opus"})
	got := e.Detail()
	if got["kind"] != "answer_codec_not_offered" {
		t.Fatalf("kind=%v", got["kind"])
	}
	if got["action"] != "ack_then_bye" {
		t.Fatalf("action=%v", got["action"])
	}
	if v, ok := got["sip_response_sent"]; !ok || v != nil {
		t.Fatalf("sip_response_sent must be present and nil, got (%v,%v)", v, ok)
	}
	if !reflect.DeepEqual(got["offered"], []string{"PCMU"}) ||
		!reflect.DeepEqual(got["answered"], []string{"opus"}) {
		t.Fatalf("offered/answered wrong: %#v", got)
	}
}

func TestSDPAbsentDetail(t *testing.T) {
	e := SDPAbsent()
	got := e.Detail()
	if got["kind"] != "sdp_absent" || got["action"] != "ack_then_bye" {
		t.Fatalf("bad detail: %#v", got)
	}
	if v, ok := got["sip_response_sent"]; !ok || v != nil {
		t.Fatalf("sip_response_sent must be present and nil, got (%v,%v)", v, ok)
	}
}

func TestSRTPOfferedButDisabledDetail(t *testing.T) {
	got := SRTPOfferedButDisabled().Detail()
	if got["kind"] != "srtp_offered_but_disabled" || got["sip_response_sent"] != 488 || got["offered_profile"] != "RTP/SAVP" {
		t.Fatalf("bad detail: %#v", got)
	}
}
