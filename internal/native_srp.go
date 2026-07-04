package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const nativeSRP4096ExponentSize = 38

var (
	nativeSRP4096N = nativeSRPMustHex("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
		"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
		"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
		"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
		"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
		"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
		"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
		"B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
		"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
		"E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
		"99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
		"04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
		"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
		"D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
		"FFFFFFFFFFFFFFFF")
	nativeSRP4096G = big.NewInt(5)
)

func nativeSRPClientPublicA(ephemeralPrivate *big.Int) (*big.Int, error) {
	if ephemeralPrivate == nil || ephemeralPrivate.Sign() == 0 {
		return nil, fmt.Errorf("cannot calculate SRP A without an ephemeral private value")
	}
	return new(big.Int).Exp(nativeSRP4096G, ephemeralPrivate, nativeSRP4096N), nil
}

func nativeSRPGenerateEphemeralPrivate() (*big.Int, error) {
	return nativeSRPGenerateEphemeralPrivateFrom(rand.Reader)
}

func nativeSRPGenerateEphemeralPrivateFrom(reader io.Reader) (*big.Int, error) {
	if reader == nil {
		return nil, fmt.Errorf("random reader is required")
	}
	bytes := make([]byte, nativeSRP4096ExponentSize)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return nil, fmt.Errorf("generate SRP ephemeral private value: %w", err)
	}
	ephemeralPrivate := new(big.Int).SetBytes(bytes)
	if ephemeralPrivate.Sign() == 0 {
		return nil, fmt.Errorf("generated SRP ephemeral private value is zero")
	}
	return ephemeralPrivate, nil
}

func nativeSRPClientPublicHex(ephemeralPrivate *big.Int) (string, error) {
	publicA, err := nativeSRPClientPublicA(ephemeralPrivate)
	if err != nil {
		return "", err
	}
	return nativeSRPServerStyleHex(publicA), nil
}

func nativeSRPClientRawKey(x, ephemeralPrivate, serverB, u, k *big.Int) ([]byte, error) {
	if x == nil || x.Sign() == 0 {
		return nil, fmt.Errorf("cannot calculate SRP key without x")
	}
	if ephemeralPrivate == nil || ephemeralPrivate.Sign() == 0 {
		return nil, fmt.Errorf("cannot calculate SRP key without an ephemeral private value")
	}
	if u == nil || u.Sign() == 0 {
		return nil, fmt.Errorf("cannot calculate SRP key without u")
	}
	if k == nil || k.Sign() == 0 {
		return nil, fmt.Errorf("cannot calculate SRP key without k")
	}
	if !nativeSRPIsPublicValid(serverB) {
		return nil, fmt.Errorf("invalid SRP server public value")
	}

	exponent := new(big.Int).Mul(u, x)
	exponent.Add(exponent, ephemeralPrivate)

	base := new(big.Int).Exp(nativeSRP4096G, x, nativeSRP4096N)
	base.Mul(base, k)
	base.Sub(serverB, base)
	base.Mod(base, nativeSRP4096N)

	premaster := new(big.Int).Exp(base, exponent, nativeSRP4096N)
	sum := sha256.Sum256([]byte(premaster.Text(16)))
	return sum[:], nil
}

func nativeSRPClientU(clientA, serverB *big.Int) (*big.Int, error) {
	if !nativeSRPIsPublicValid(clientA) || !nativeSRPIsPublicValid(serverB) {
		return nil, fmt.Errorf("both SRP public values must be valid")
	}
	sum := sha256.Sum256([]byte(nativeSRPServerStyleHex(clientA) + nativeSRPServerStyleHex(serverB)))
	return new(big.Int).SetBytes(sum[:]), nil
}

func nativeSRPServerProof(salt []byte, username string, clientA, serverB *big.Int, key []byte) ([]byte, error) {
	if !nativeSRPIsPublicValid(clientA) || !nativeSRPIsPublicValid(serverB) {
		return nil, fmt.Errorf("both SRP public values must be valid")
	}
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("SRP key must be %d bytes", sha256.Size)
	}

	nHash := sha256.Sum256(nativeSRP4096N.Bytes())
	gHash := sha256.Sum256(nativeSRP4096G.Bytes())
	groupXOR := make([]byte, sha256.Size)
	for i := range groupXOR {
		groupXOR[i] = nHash[i] ^ gHash[i]
	}
	groupHash := sha256.Sum256(groupXOR)
	userHash := sha256.Sum256([]byte(username))

	h := sha256.New()
	h.Write(groupHash[:])
	h.Write(userHash[:])
	h.Write(salt)
	h.Write(clientA.Bytes())
	h.Write(serverB.Bytes())
	h.Write(key)
	return h.Sum(nil), nil
}

func nativeSRPClientProof(clientA *big.Int, serverProof, key []byte) ([]byte, error) {
	if !nativeSRPIsPublicValid(clientA) {
		return nil, fmt.Errorf("SRP client public value must be valid")
	}
	if len(serverProof) != sha256.Size {
		return nil, fmt.Errorf("SRP server proof must be %d bytes", sha256.Size)
	}
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("SRP key must be %d bytes", sha256.Size)
	}

	h := sha256.New()
	h.Write(clientA.Bytes())
	h.Write(serverProof)
	h.Write(key)
	return h.Sum(nil), nil
}

func nativeSRPIsPublicValid(public *big.Int) bool {
	if public == nil {
		return false
	}
	if new(big.Int).Mod(public, nativeSRP4096N).Sign() == 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, public, nativeSRP4096N).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return true
}

func nativeSRPServerStyleHex(n *big.Int) string {
	return strings.TrimLeft(strings.ToLower(n.Text(16)), "0")
}

func nativeSRPMustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(strings.ReplaceAll(s, " ", ""), 16)
	if !ok {
		panic("invalid SRP hex constant")
	}
	return n
}
