//go:build (cgo && (darwin || linux)) || windows

package internal

import "testing"

func TestGetSharedLibCoreKeepsAccountPerWrapper(t *testing.T) {
	coreLibMu.Lock()
	previous := coreLib
	coreLib = &SharedLibCore{}
	coreLibMu.Unlock()
	defer func() {
		coreLibMu.Lock()
		coreLib = previous
		coreLibMu.Unlock()
	}()

	first, err := GetSharedLibCore("first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GetSharedLibCore("second")
	if err != nil {
		t.Fatal(err)
	}

	firstCore := first.InnerCore.(*SharedLibCore)
	secondCore := second.InnerCore.(*SharedLibCore)
	if firstCore == secondCore {
		t.Fatal("expected separate account wrappers")
	}
	if firstCore.accountName != "first" || secondCore.accountName != "second" {
		t.Fatalf("account names = %q, %q", firstCore.accountName, secondCore.accountName)
	}
}
