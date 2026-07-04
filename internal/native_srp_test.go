package internal

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

const nativeSRPTestUserA = "58803b8fea0aaf137714185eae673f7adc56ae92e26bc4a97065a6a464f75d9942905782925e0a8fa93427151b6acd447ac883c85dd68b55b90b07e96aa475004f76f5b7cba26365b426a0cb239eee21bb46ddbc7c5a0c86f3abe5c12aebb1343d5c3e345ea3f48e491b2abada6bbb621896f26eafdfaf6e52838d97ffec3b69e30f8920e8f1cfc87c612762f9b215384d22b9666bfdcdfc1a71229063854ca5f640866ecb93214d6f873cab9c44eb2f1f3b2eb953a0d0589e215df172b311b7ffba02f5951e3828e262a047f6327056db00fa7a723140ed96d425f6847ad570909f5b1190e6a8d40ec5458b88e7f1cced26c2d772a4511ac2de9f9f52b4237365d29e9df66a3b1440242c5d7e2578eb0215a2179e601ef84bec959cc6cfdad2f2d6db5d745998591ad1c76107874fd49076f38f4304011aff1a8a064ff7c3dc0b5050910b5ccb0ad93f34e49948e2cd6f6619797f205ab94b9b5e91ed21acdda2b59c6e3107739b79faeeb5c426d20bc52ec10d3625531c13f0c7039252258ecf19fa65dd85b80a89061ce4f3888ca168744d32fc97622144fc293255cd5881bdbfd258768f41026b7520f98eabad2ee9834fa835d14fc11591b22da4a55f3edae8a4f70b8e3e7bdf1d660ad9308ce41402e608fe07936390a4941a4b3a7b6adb196981b2a4d11810457e5767e10bb3ddca70e14bc259e4567365c3f326b3c8"

func TestNativeSRPGenerateEphemeralPrivate(t *testing.T) {
	source := bytes.Repeat([]byte{0x7f}, nativeSRP4096ExponentSize)
	ephemeralPrivate, err := nativeSRPGenerateEphemeralPrivateFrom(bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ephemeralPrivate.Bytes(), source; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}

	if _, err := nativeSRPGenerateEphemeralPrivateFrom(nil); err == nil {
		t.Fatal("expected nil reader error")
	}
	if _, err := nativeSRPGenerateEphemeralPrivateFrom(bytes.NewReader(source[:nativeSRP4096ExponentSize-1])); err == nil {
		t.Fatal("expected short read error")
	}
	if _, err := nativeSRPGenerateEphemeralPrivateFrom(bytes.NewReader(make([]byte, nativeSRP4096ExponentSize))); err == nil {
		t.Fatal("expected zero ephemeral error")
	}
}

func TestNativeSRPGenerateEphemeralPrivateUsesCryptoRand(t *testing.T) {
	ephemeralPrivate, err := nativeSRPGenerateEphemeralPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if ephemeralPrivate.Sign() == 0 {
		t.Fatal("expected non-zero ephemeral private value")
	}
}

func TestNativeSRPClientRawKeyMatchesOfficialVector(t *testing.T) {
	x := nativeSRPMustHex("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773")
	a := nativeSRPMustHex("f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06")
	serverB := nativeSRPMustHex("780a5495cbf731d2463fd01d28822e7d9ccf697c4239d5151f85666aa06b3767e0301b54cfad3bd2b526d4d8a1d96492e59c8d8ecddca96b7e288f186155ffa57b50df6bc2103b6004400b797334a22d9dd234b40142a5ab714ea6070d2ed55096049f50efba99862b72f7e7aee51ed71ba6663fff570cc713d456316f3535630e87a245f09b0791c6e687baa65bf2dfb5c17e50c250256cdad4c9851a2484e88326888060ae9578b5a60e0c85143b25f4fb4fca794e266a4359642da085672d6a3b881649a387875685aeb1ae3d809bf7818dcad596c6e29d566ae87c0ad645a0fcc2eb4f066c097670adf48cf0954918fda4dc30588261321d592f890eed87a950d387b48cf6b4a49f9d497323f683091ae6a4efe675d6bfc4393c0c3d54c9adad65b8dd3a7b7e85cd5d31e97bebc8f23b370348dab53903ec5085cbf65de5e5491f417e5bf9953f081e788f36c26cbe00664a1256c4befb00765ea7e432af189521442c186f14442b1957e444426f740f363ebda943da2bb3b18a13e2f41be9cc3ca0a1b111f6983f9b8d0ee0f4b573c6042fbc0ca029821ebe517ed0755a94f42d32b0abef9240af0f37b5fe0e90c4ca83acf91d28a7f3acff5657bf69fdb7747e380b23fd437f637da2f7ebcf8733a69a75715fe3894e1799906b48e3ae818332cf5f9533e7af5a1f065f907c8f31fe778fa2da853e69926fc551d6b3ae")
	u := nativeSRPMustHex("dad353365f78590c1857b29f16e3a947df4707868e2dd2d2b4eafd35c8c854a1")
	k := nativeSRPMustHex("4832374a524b354d344e424a584f42434f45544356584a484641")
	expectedKey, err := hex.DecodeString("f6bef3d6fa5a08a849bf61041cd5b3185c16aede851c819a3644fa7e918c4da6")
	if err != nil {
		t.Fatal(err)
	}

	clientA, err := nativeSRPClientPublicA(a)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeSRPIsPublicValid(clientA) {
		t.Fatal("expected client public value to be valid")
	}
	userA, err := nativeSRPClientPublicHex(a)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := userA, nativeSRPTestUserA; got != want {
		t.Fatalf("got userA %s, want %s", got, want)
	}
	key, err := nativeSRPClientRawKey(x, a, serverB, u, k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, expectedKey) {
		t.Fatalf("got %x, want %x", key, expectedKey)
	}
}

func TestNativeSRPClientU(t *testing.T) {
	clientA := nativeSRPMustHex("6dbff3c06aef910a938f47636087b98df6bd546c1bdc32b39f6dd86e31d1e7cb")
	serverB := nativeSRPMustHex("2aa6be093ce19b068109c36a903dc4efed86e17f23595f158e47930746bc2c9c")
	u, err := nativeSRPClientU(clientA, serverB)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(u.Bytes()), "5a3d39d17f64d90c5b0aa932a18b76aa01195e235cfc0a796f333edde352f095"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestNativeSRPProofs(t *testing.T) {
	clientA, serverB, key := nativeSRPProofFixture(t)
	salt, err := hex.DecodeString("2e1a520e226f461e840e40e0")
	if err != nil {
		t.Fatal(err)
	}
	serverProof, err := nativeSRPServerProof(salt, "Polly@cracker.example", clientA, serverB, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(serverProof), "1df01191836e040255414c8196fb7f8547f58b0a8afc495ef94578ed23135fbe"; got != want {
		t.Fatalf("got server proof %s, want %s", got, want)
	}

	clientProof, err := nativeSRPClientProof(clientA, serverProof, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(clientProof), "5e0aef0138a059ce162655f10d1736b209b9951d856bf021cb417f2b542e3db8"; got != want {
		t.Fatalf("got client proof %s, want %s", got, want)
	}
}

func TestNativeSRPRejectsInvalidPublicValues(t *testing.T) {
	if nativeSRPIsPublicValid(nil) {
		t.Fatal("nil public value should be invalid")
	}
	if nativeSRPIsPublicValid(nativeSRP4096N) {
		t.Fatal("modulus multiple should be invalid")
	}
	if _, err := nativeSRPClientRawKey(nativeSRPMustHex("1"), nativeSRPMustHex("2"), nativeSRP4096N, nativeSRPMustHex("3"), nativeSRPMustHex("4")); err == nil {
		t.Fatal("expected invalid server public value")
	}
}

func nativeSRPProofFixture(t *testing.T) (*big.Int, *big.Int, []byte) {
	t.Helper()
	a := nativeSRPMustHex("62c07608fa04d2fdfeb5e281fe6c459d4ff03e6aa439a1a5b399a4648f8ddd7e")
	b := nativeSRPMustHex("c18136e73ea06f5e795a6ad8f8140c450fd98027d8ea8cfa6aea0e8c7e73c88a")
	key, err := hex.DecodeString("1fad6d1c06537a32c672d90eff92a9ad88fa7f5f333605d6d0bf3712b4a57078")
	if err != nil {
		t.Fatal(err)
	}
	clientA := new(big.Int).Exp(nativeSRP4096G, a, nativeSRP4096N)
	serverB := new(big.Int).Exp(nativeSRP4096G, b, nativeSRP4096N)
	return clientA, serverB, key
}
