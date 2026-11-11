package policy

import "testing"

func TestPromptLookup(t *testing.T) {
	p := &Policy{Prompts: []Prompt{
		{Name: "prompt-1", Path: "/srv/prompts/one.wav"},
		{Name: "prompt-2", Path: "/srv/prompts/two.wav"},
	}}
	if path, ok := p.Prompt("prompt-1"); !ok || path != "/srv/prompts/one.wav" {
		t.Fatalf("Prompt(prompt-1)=%q,%v want /srv/prompts/one.wav,true", path, ok)
	}
	if _, ok := p.Prompt("nope"); ok {
		t.Fatal("Prompt(nope) resolved an unregistered name")
	}
	if _, ok := p.Prompt(""); ok {
		t.Fatal("Prompt(\"\") resolved the empty name")
	}
}

func TestValidateRejectsBadPrompts(t *testing.T) {
	base := func() *Policy {
		return &Policy{
			Auth:   Auth{BearerTokenFile: "x"},
			Limits: defaults().Limits,
		}
	}
	t.Run("empty name", func(t *testing.T) {
		p := base()
		p.Prompts = []Prompt{{Name: "", Path: "/a.wav"}}
		if err := p.validate(); err == nil {
			t.Fatal("validate accepted a prompt with an empty name")
		}
	})
	t.Run("empty path", func(t *testing.T) {
		p := base()
		p.Prompts = []Prompt{{Name: "p1", Path: ""}}
		if err := p.validate(); err == nil {
			t.Fatal("validate accepted a prompt with an empty path")
		}
	})
	t.Run("duplicate name", func(t *testing.T) {
		p := base()
		p.Prompts = []Prompt{{Name: "p1", Path: "/a.wav"}, {Name: "p1", Path: "/b.wav"}}
		if err := p.validate(); err == nil {
			t.Fatal("validate accepted duplicate prompt names")
		}
	})
}
