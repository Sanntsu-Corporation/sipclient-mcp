package sip

import "testing"

func unkeyedHas(p *ConnectionPool, c Connection) bool {
	p.RLock()
	defer p.RUnlock()
	_, ok := p.unkeyed[c]
	return ok
}

func unkeyedLen(p *ConnectionPool) int {
	p.RLock()
	defer p.RUnlock()
	return len(p.unkeyed)
}

func mapLen(p *ConnectionPool) int {
	p.RLock()
	defer p.RUnlock()
	return len(p.m)
}

func TestAddOrTrackOnAFreeKeyIsAnAdd(t *testing.T) {
	p := NewConnectionPool()
	c, _ := padPair(t)
	if !p.AddOrTrack("k", c) {
		t.Fatal("AddOrTrack on a free key returned false")
	}
	if got, ok := poolEntry(&p, "k"); !ok || got != c {
		t.Fatalf("k holds %p (present=%v), want %p", got, ok, c)
	}
	if n := unkeyedLen(&p); n != 0 {
		t.Fatalf("%d tracked connections after a store, want 0", n)
	}
}

func TestAConnectionRefusedAKeyIsTrackedAndClosedByClear(t *testing.T) {
	p := NewConnectionPool()
	holder, holderPeer := padPair(t)
	out, outPeer := padPair(t)
	p.Add("k", holder)
	if p.AddOrTrack("k", out) {
		t.Fatal("AddOrTrack on a held key returned true")
	}
	if got, ok := poolEntry(&p, "k"); !ok || got != holder {
		t.Fatalf("k holds %p (present=%v), want the holder %p", got, ok, holder)
	}
	if !unkeyedHas(&p, out) {
		t.Fatal("the refused connection is not tracked")
	}
	p.Clear()
	if !peerSeesClose(t, holderPeer) {
		t.Fatal("Clear did not close the holder")
	}
	if !peerSeesClose(t, outPeer) {
		t.Fatal("Clear did not close the tracked connection")
	}
}

func TestCloseAndDeleteForgetsATrackedConnectionAndPromotesOneWhenTheHolderExits(t *testing.T) {
	p := NewConnectionPool()
	holder, _ := padPair(t)
	out, _ := padPair(t)
	p.Add("k", holder)
	p.AddOrTrack("k", out)
	p.CloseAndDelete(holder, "k")
	if got, ok := poolEntry(&p, "k"); !ok || got != out {
		t.Fatalf("k holds %p (present=%v), want the promoted %p", got, ok, out)
	}
	if unkeyedHas(&p, out) {
		t.Fatal("the promoted connection is still tracked")
	}
}

func TestCloseAndDeleteOfATrackedConnectionForgetsItAndKeepsTheHolder(t *testing.T) {
	p := NewConnectionPool()
	holder, _ := padPair(t)
	out, outPeer := padPair(t)
	p.Add("k", holder)
	p.AddOrTrack("k", out)
	p.CloseAndDelete(out, "k")
	if !peerSeesClose(t, outPeer) {
		t.Fatal("the tracked connection was not closed")
	}
	if got, ok := poolEntry(&p, "k"); !ok || got != holder {
		t.Fatalf("k holds %p (present=%v), want the holder %p", got, ok, holder)
	}
	if n := unkeyedLen(&p); n != 0 {
		t.Fatalf("%d tracked connections, want 0", n)
	}
}

func TestAnExitingTrackedConnectionDoesNotDisplaceTheLiveHolder(t *testing.T) {
	p := NewConnectionPool()
	holder, _ := padPair(t)
	o1, _ := padPair(t)
	o2, _ := padPair(t)
	p.Add("k", holder)
	p.AddOrTrack("k", o1)
	p.AddOrTrack("k", o2)
	p.CloseAndDelete(o1, "k")
	if got, ok := poolEntry(&p, "k"); !ok || got != holder {
		t.Fatalf("k holds %p (present=%v), want the holder %p", got, ok, holder)
	}
	if !unkeyedHas(&p, o2) {
		t.Fatal("the other tracked connection was dropped")
	}
}

func TestPromotionOnlyHandsAKeyToAConnectionThatWantedIt(t *testing.T) {
	p := NewConnectionPool()
	h, _ := padPair(t)
	h2, _ := padPair(t)
	o2, _ := padPair(t)
	p.Add("k", h)
	p.Add("k2", h2)
	p.AddOrTrack("k2", o2)
	p.CloseAndDelete(h, "k")
	if got, ok := poolEntry(&p, "k"); ok {
		t.Fatalf("k holds %p, want no entry (nobody wanted it)", got)
	}
	if got, ok := poolEntry(&p, "k2"); !ok || got != h2 {
		t.Fatalf("k2 holds %p (present=%v), want %p", got, ok, h2)
	}
	if !unkeyedHas(&p, o2) {
		t.Fatal("o2 left the tracked set")
	}

	h3, _ := padPair(t)
	o1, _ := padPair(t)
	p.Add("k", h3)
	p.AddOrTrack("k", o1)
	p.CloseAndDelete(h3, "k")
	if got, ok := poolEntry(&p, "k"); !ok || got != o1 {
		t.Fatalf("k holds %p (present=%v), want %p", got, ok, o1)
	}
	if got, ok := poolEntry(&p, "k2"); !ok || got != h2 {
		t.Fatalf("k2 holds %p (present=%v), want %p", got, ok, h2)
	}
	if !unkeyedHas(&p, o2) {
		t.Fatal("o2 left the tracked set")
	}
}

func TestPromotionChainsThroughTrackedConnections(t *testing.T) {
	p := NewConnectionPool()
	h, _ := padPair(t)
	o2, _ := padPair(t)
	o3, _ := padPair(t)
	p.Add("k", h)
	p.AddOrTrack("k", o2)
	p.AddOrTrack("k", o3)
	p.CloseAndDelete(h, "k")
	first, ok := poolEntry(&p, "k")
	if !ok || (first != Connection(o2) && first != Connection(o3)) {
		t.Fatalf("k holds %p (present=%v), want one of %p / %p", first, ok, o2, o3)
	}
	other := Connection(o2)
	if first == other {
		other = o3
	}
	if unkeyedHas(&p, first) || !unkeyedHas(&p, other) {
		t.Fatal("after the first promotion the tracked set is wrong")
	}
	p.CloseAndDelete(first, "k")
	if got, ok := poolEntry(&p, "k"); !ok || got != other {
		t.Fatalf("k holds %p (present=%v), want %p", got, ok, other)
	}
	if n := unkeyedLen(&p); n != 0 {
		t.Fatalf("%d tracked connections, want 0", n)
	}
}

func TestPromotionSkipsATrackedConnectionAlreadyClosed(t *testing.T) {
	p := NewConnectionPool()
	h, _ := padPair(t)
	dead, _ := padPair(t)
	p.Add("k", h)
	p.AddOrTrack("k", dead)
	dead.Close() // its reader has not run yet
	p.CloseAndDelete(h, "k")
	if got, ok := poolEntry(&p, "k"); ok {
		t.Fatalf("k holds %p, want no entry (the only candidate is closed)", got)
	}

	h2, _ := padPair(t)
	live, _ := padPair(t)
	p.Add("k", h2)
	p.AddOrTrack("k", live)
	p.CloseAndDelete(h2, "k")
	if got, ok := poolEntry(&p, "k"); !ok || got != live {
		t.Fatalf("k holds %p (present=%v), want the live %p", got, ok, live)
	}
}

// Pin: no single mutation of the pool reddens this; it documents that readers
// exiting after Clear neither panic nor re-create a key.
func TestCloseAndDeleteAfterClearDoesNotRepopulate(t *testing.T) {
	p := NewConnectionPool()
	h, _ := padPair(t)
	out, _ := padPair(t)
	p.Add("k", h)
	p.AddOrTrack("k", out)
	p.Clear()
	p.CloseAndDelete(out, "k")
	p.CloseAndDelete(h, "k")
	if n := mapLen(&p); n != 0 {
		t.Fatalf("%d keys after Clear and the readers' exits, want 0", n)
	}
	if n := unkeyedLen(&p); n != 0 {
		t.Fatalf("%d tracked connections, want 0", n)
	}
}
