package media

import (
	"strings"
	"testing"
)

func TestGenerateCryptoAttrRoundTrip(t *testing.T) {
	cp, line, err := GenerateCryptoAttr()
	if err != nil {
		t.Fatalf("GenerateCryptoAttr: %v", err)
	}
	if cp.Suite != SuiteAESCM128HMACSHA180 {
		t.Fatalf("suite=%q", cp.Suite)
	}
	if !strings.HasPrefix(line, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:") {
		t.Fatalf("unexpected line format: %q", line)
	}
	got, err := ParseCryptoAttr(line)
	if err != nil {
		t.Fatalf("ParseCryptoAttr: %v", err)
	}
	if got.MasterKey != cp.MasterKey || got.MasterSalt != cp.MasterSalt || got.Suite != cp.Suite {
		t.Fatal("round-trip lost key material")
	}
}

func TestGenerateCryptoAttrIsRandom(t *testing.T) {
	a, _, _ := GenerateCryptoAttr()
	b, _, _ := GenerateCryptoAttr()
	if a.MasterKey == b.MasterKey && a.MasterSalt == b.MasterSalt {
		t.Fatal("two generations produced identical key material")
	}
}

func TestParseCryptoAttrRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80", // no key-params
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:!", // undecodable base64
		"a=crypto:1 SOME_OTHER_SUITE inline:AAAA",     // unsupported suite
	} {
		if _, err := ParseCryptoAttr(bad); err == nil {
			t.Fatalf("ParseCryptoAttr(%q) accepted invalid input", bad)
		}
	}
}

func TestParseCryptoAttrAcceptsBareValue(t *testing.T) {
	_, line, _ := GenerateCryptoAttr()
	bare := strings.TrimPrefix(line, "a=crypto:")
	if _, err := ParseCryptoAttr(bare); err != nil {
		t.Fatalf("ParseCryptoAttr(bare)=%v", err)
	}
}
