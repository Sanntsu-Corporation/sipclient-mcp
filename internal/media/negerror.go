package media

import "fmt"

// The §11.2 detail.kind taxonomy. srtp_required_but_peer_answered_avp is
// DEFINED here for forward-compatibility with W4 but its trigger is not
// reachable this wave (design spec §7): no real SRTP session is ever offered.
const (
	KindNoCommonCodec               = "no_common_codec"
	KindSRTPRequiredPeerOfferedAVP  = "srtp_required_but_peer_offered_avp"
	KindAnswerCodecNotOffered       = "answer_codec_not_offered"
	KindSRTPRequiredPeerAnsweredAVP = "srtp_required_but_peer_answered_avp"
	KindSDPAbsent                   = "sdp_absent"
	KindSDPUnparseable              = "sdp_unparseable"
	KindSRTPOfferedButDisabled      = "srtp_offered_but_disabled"
	KindAnswerRejectedAudio         = "answer_rejected_audio"
)

// NegotiationError is what BuildAnswer and ParseAnswer return on failure. It
// carries the exact §11.2 detail object. Answer-side errors set responseSent to
// 488; offer-side errors set it to nil and action to "ack_then_bye" (§11.2.1).
type NegotiationError struct {
	Kind            string
	Offered         []string
	Acceptable      []string
	Answered        []string
	OfferedProfile  string
	RequiredProfile string
	responseSent    *int   // 488 answer-side; nil offer-side
	action          string // "ack_then_bye" offer-side; "" answer-side
	msg             string
}

func (e *NegotiationError) Error() string { return e.msg }

// Detail renders §11.2's detail object. sip_response_sent is ALWAYS present:
// 488 answer-side, JSON null (a nil interface value) offer-side.
func (e *NegotiationError) Detail() map[string]any {
	d := map[string]any{"kind": e.Kind}
	switch e.Kind {
	case KindNoCommonCodec:
		d["offered"], d["acceptable"] = e.Offered, e.Acceptable
	case KindSRTPOfferedButDisabled:
		d["offered_profile"] = e.OfferedProfile
	case KindSRTPRequiredPeerOfferedAVP, KindSRTPRequiredPeerAnsweredAVP:
		d["offered_profile"], d["required_profile"] = e.OfferedProfile, e.RequiredProfile
	case KindAnswerCodecNotOffered:
		d["offered"], d["answered"] = e.Offered, e.Answered
	}
	if e.responseSent != nil {
		d["sip_response_sent"] = *e.responseSent
	} else {
		d["sip_response_sent"] = nil
	}
	if e.action != "" {
		d["action"] = e.action
	}
	return d
}

func code488() *int { c := 488; return &c }

// ---- answer-side (we are the UAS; 488 goes on the wire) --------------------

// NoCommonCodec builds the error for a peer offer with no codec this UA accepts.
func NoCommonCodec(offered, acceptable []string) *NegotiationError {
	return &NegotiationError{
		Kind: KindNoCommonCodec, Offered: offered, Acceptable: acceptable,
		responseSent: code488(),
		msg:          fmt.Sprintf("no codec in common: peer offered %v, this UA accepts %v", offered, acceptable),
	}
}

// SRTPPeerOfferedAVP builds the error for a peer offer this UA's srtp policy
// cannot use: RTP/AVP when it requires SRTP, or (policy optional) an RTP/SAVP
// offer without a usable a=crypto. offered is the profile the peer offered.
func SRTPPeerOfferedAVP(policy SRTPPolicy, offered string) *NegotiationError {
	if offered == "" {
		offered = "RTP/AVP"
	}
	msg := "srtp=required but peer offered RTP/AVP; refusing to send unencrypted media"
	if offered != "RTP/AVP" {
		msg = "srtp=" + string(policy) + " but the peer's " + offered + " offer carries no usable SDES key (a=crypto)"
	}
	return &NegotiationError{
		Kind: KindSRTPRequiredPeerOfferedAVP, OfferedProfile: offered, RequiredProfile: "RTP/SAVP",
		responseSent: code488(), msg: msg,
	}
}

// SRTPOfferedButDisabled builds the error for a peer offering RTP/SAVP when
// this UA's srtp policy is disabled and no other stream is usable (A-5).
func SRTPOfferedButDisabled() *NegotiationError {
	return &NegotiationError{
		Kind: KindSRTPOfferedButDisabled, OfferedProfile: "RTP/SAVP",
		responseSent: code488(),
		msg:          "srtp=disabled but peer offered RTP/SAVP; refusing to answer it as plain RTP",
	}
}

// ---- offering-side (we are the UAC; ACK-then-BYE, no 488 available) ---------

// AnswerCodecNotOffered builds the error for a peer answering a codec we
// never offered.
func AnswerCodecNotOffered(offered, answered []string) *NegotiationError {
	return &NegotiationError{
		Kind: KindAnswerCodecNotOffered, Offered: offered, Answered: answered, action: "ack_then_bye",
		msg: fmt.Sprintf("peer answered a codec we did not offer: offered %v, answered %v", offered, answered),
	}
}

// SRTPPeerAnsweredAVP builds the error for a peer answering unencrypted
// RTP/AVP when this UA requires SRTP.
func SRTPPeerAnsweredAVP() *NegotiationError {
	return &NegotiationError{
		Kind: KindSRTPRequiredPeerAnsweredAVP, OfferedProfile: "RTP/AVP", RequiredProfile: "RTP/SAVP",
		action: "ack_then_bye",
		msg:    "srtp=required but peer answered RTP/AVP; tearing down",
	}
}

// SDPAbsent builds the error for a peer 200 OK carrying no SDP body.
func SDPAbsent() *NegotiationError {
	return &NegotiationError{Kind: KindSDPAbsent, action: "ack_then_bye",
		msg: "peer 200 OK carried no SDP body"}
}

// SDPUnparseable builds the error for a peer SDP body that failed to parse.
func SDPUnparseable() *NegotiationError {
	return &NegotiationError{Kind: KindSDPUnparseable, action: "ack_then_bye",
		msg: "peer 200 OK SDP body could not be parsed"}
}

// AnswerRejectedAudio builds the error for a peer answering our only audio
// stream with port 0 (RFC 3264 6: the stream is rejected, so there is no media
// to carry; A-15, owner ruling). The call is ended ACK-then-BYE.
func AnswerRejectedAudio() *NegotiationError {
	return &NegotiationError{Kind: KindAnswerRejectedAudio, action: "ack_then_bye",
		msg: "peer's answer rejected our audio stream (m=audio port 0); ending the call"}
}
