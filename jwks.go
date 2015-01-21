package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var (
	MalformedTokenError        = errors.New("Malformed token.")
	InvalidKeyStoreError       = errors.New("Invalid key store.")
	KeyNotFoundError           = errors.New("Key not found.")
	AlgorithmNotSupportedError = errors.New("Algorithm not supported.")
	InvalidSignatureError      = errors.New("Invalid token signature.")
	UnspecifiedURLError        = errors.New("Key store URL not specified.")
)

type ReadKeyFunction func(*JKSKey) (interface{}, error)
type VerifyFunction func(*ParsedToken, interface{}, crypto.Hash) error

type Verifier struct {
	verify VerifyFunction
	hash   crypto.Hash
}

/* Map from values that appear in the "alg" field of a JWS header to the
   corresponding signature hash function. */
var jwsVerifiers = map[string]Verifier{
	"HS256": {verifyHMAC, crypto.SHA256},
	"HS384": {verifyHMAC, crypto.SHA384},
	"HS512": {verifyHMAC, crypto.SHA512},
	"RS256": {verifyRSA, crypto.SHA256},
	"RS384": {verifyRSA, crypto.SHA384},
	"RS512": {verifyRSA, crypto.SHA512},
	"EC256": {verifyECDSA, crypto.SHA256},
	"EC384": {verifyECDSA, crypto.SHA384},
	"EC512": {verifyECDSA, crypto.SHA512},
}

/* Map from values that appear in the "crv" field of JWK records. */
var jksCurveTable = map[string]func() elliptic.Curve{
	"P-224": elliptic.P224,
	"P-256": elliptic.P256,
	"P-384": elliptic.P384,
	"P-521": elliptic.P521,
}

/* Map from "kty" values in JKS records to the function that converts the key for storage. */
var jwtKtyDispatch = map[string]ReadKeyFunction{
	"RSA": readRSA,
	"EC":  readECDSA,
	"oct": readSymmetric,
}

type KeyTable map[string]interface{}

type KeyStore struct {
	URL      string
	keys     KeyTable
	updates  chan KeyTable
	stop     chan bool
	interval time.Duration
}

func New(url string, updateInterval time.Duration) *KeyStore {
	s := &KeyStore{
		keys:     nil,
		URL:      url,
		interval: 0,
		updates:  make(chan KeyTable, 4),
		stop:     make(chan bool, 4),
	}
	s.SetUpdateInterval(updateInterval)
	return s
}

func (s *KeyStore) SetUpdateInterval(interval time.Duration) {
	if interval != s.interval {
		if s.interval != 0 {
			s.stop <- true
		}
		if interval != 0 {
			go s.updateThread(time.Tick(interval))
		}
		s.interval = interval
	}
}

func (s *KeyStore) Update() error {
	table, err := s.fetchKeyTable()
	if err == nil {
		s.keys = table
	}
	return err
}

func (s *KeyStore) updateThread(signals <-chan time.Time) {
	for {
		select {
		case <-signals:
			table, _ := s.fetchKeyTable()
			s.updates <- table
		case <-s.stop:
			return
		}
	}
}

func base64URLDecode(s string) ([]byte, error) {
	padding := [4]string{"", "", "==", "="}
	seq := io.MultiReader(strings.NewReader(s), strings.NewReader(padding[len(s)%4]))
	decoder := base64.NewDecoder(base64.URLEncoding, seq)
	return ioutil.ReadAll(decoder)
}

type JKSKey struct {
	Kid, Kty, Crv, N, E, X, Y, K string
}

func readSymmetric(key *JKSKey) (interface{}, error) {
	if len(key.K) == 0 {
		return nil, InvalidKeyStoreError
	}
	return base64URLDecode(key.K)
}

func readRSA(key *JKSKey) (interface{}, error) {
	if len(key.N) == 0 || len(key.E) == 0 {
		return nil, InvalidKeyStoreError
	}
	ns, errN := base64URLDecode(key.N)
	es, errE := base64URLDecode(key.E)
	if errN != nil || errE != nil {
		return nil, InvalidKeyStoreError
	}
	var n, e big.Int
	n.SetBytes(ns)
	e.SetBytes(es)
	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func readECDSA(key *JKSKey) (interface{}, error) {
	if len(key.X) == 0 || len(key.Y) == 0 {
		return nil, InvalidKeyStoreError
	}
	xs, errX := base64URLDecode(key.X)
	ys, errY := base64URLDecode(key.Y)
	if errX != nil || errY != nil {
		return nil, InvalidKeyStoreError
	}
	curve := jksCurveTable[key.Crv]
	if curve == nil {
		return nil, InvalidKeyStoreError
	}
	var x, y big.Int
	x.SetBytes(xs)
	y.SetBytes(ys)
	return &ecdsa.PublicKey{X: &x, Y: &y, Curve: curve()}, nil
}

func (s *KeyStore) fetchKeyTable() (KeyTable, error) {
	/* Fetch the key store JSON. */
	if s.URL == "" {
		return nil, UnspecifiedURLError
	}
	response, err := http.Get(s.URL)
	if err != nil {
		return nil, err
	}

	/* Unmarshal the key store into a temporary local structure. */
	store := struct{ Keys []JKSKey }{}
	err = json.NewDecoder(response.Body).Decode(&store)
	if err != nil {
		return nil, err
	}

	/* Try to build a new key table from the keys. */
	keys := make(KeyTable)
	for _, key := range store.Keys {
		readKey := jwtKtyDispatch[key.Kty]
		if readKey != nil {
			sk, errK := readKey(&key)
			if errK == nil {
				keys[key.Kid] = sk
			} else {
				err = errK
			}
		} else {
			err = AlgorithmNotSupportedError
		}
	}

	/* If successful, make the new key store live. */
	if err != nil {
		return nil, err
	}
	return keys, nil
}

/* JOSE header. */
type Header struct {
	Alg string
	Kid string
}

/* JWT claims set. */
type Claims struct {
	Iss   string
	Azp   string
	Aud   string
	Iat   uint
	Exp   uint
	Email string
}

/* Temporary structure representing an unmarshalled JWT. */
type ParsedToken struct {
	Header         Header
	Claims         Claims
	Signature      []byte
	SignatureInput []byte
}

func parseToken(token string, r *ParsedToken) error {
	/* Split the token into three '.'-delimited parts. */
	partsB64 := strings.Split(token, ".")
	if len(partsB64) != 3 {
		return MalformedTokenError
	}

	/* Base64-URL decode each part. */
	headerJson, ehdr := base64URLDecode(partsB64[0])
	claimsJson, eclaims := base64URLDecode(partsB64[1])
	signature, esig := base64URLDecode(partsB64[2])
	if ehdr != nil || eclaims != nil || esig != nil {
		return MalformedTokenError
	}

	/* Parse the header and claims dictionaries. */
	if err := json.Unmarshal(headerJson, &r.Header); err != nil {
		return err
	}
	if err := json.Unmarshal(claimsJson, &r.Claims); err != nil {
		return err
	}

	r.Signature = []byte(signature)
	r.SignatureInput = []byte(token[:len(partsB64[0])+1+len(partsB64[1])])
	return nil
}

func verifyHMAC(token *ParsedToken, skey interface{}, algorithm crypto.Hash) error {
	/* Is the stored key suitable? */
	key, haveKey := skey.([]byte)
	if !haveKey {
		return KeyNotFoundError
	}
	/* Calculate the HMAC of the signature input. */
	hasher := hmac.New(algorithm.New, key)
	hasher.Write(token.SignatureInput)
	signature := hasher.Sum(nil)
	/* The token signature is valid if it matches the computed signature. */
	if hmac.Equal(token.Signature, signature) {
		return nil
	}
	return InvalidSignatureError
}

func verifyRSA(token *ParsedToken, skey interface{}, algorithm crypto.Hash) error {
	/* Is the stored key suitable ? */
	publicKey, haveKey := skey.(*rsa.PublicKey)
	if !haveKey {
		return KeyNotFoundError
	}
	/* Hash the signature input. */
	hasher := algorithm.New()
	hasher.Write(token.SignatureInput)
	digest := hasher.Sum(nil)
	/* The token signature is valid if, when decrypted with the public key, it matches the computed digest. */
	return rsa.VerifyPKCS1v15(publicKey, algorithm, digest, token.Signature)
}

func verifyECDSA(token *ParsedToken, skey interface{}, algorithm crypto.Hash) error {
	/* Is the stored key suitable? */
	publicKey, haveKey := skey.(*ecdsa.PublicKey)
	if !haveKey {
		return KeyNotFoundError
	}
	/* Extract the token signature (r, s) from the two halves of token.signature. */
	digestBytes := algorithm.Size()
	if len(token.Signature) != 2*digestBytes {
		return InvalidSignatureError
	}
	var r, s big.Int
	r.SetBytes(token.Signature[:digestBytes])
	s.SetBytes(token.Signature[digestBytes:])
	/* Hash the signature input. */
	hasher := algorithm.New()
	hasher.Write(token.SignatureInput)
	digest := hasher.Sum(nil)
	/* The signature (r, s) is valid if, when decrypted with the public key, it matches the computed digest. */
	if ecdsa.Verify(publicKey, digest, &r, &s) {
		return nil
	}
	return InvalidSignatureError
}

func (s *KeyStore) Verify(token string) (*Claims, error) {
	for done := false; !done; {
		select {
		case newKeys := <-s.updates:
			s.keys = newKeys
		default:
			done = true
		}
	}

	pt := ParsedToken{}
	err := parseToken(token, &pt)
	if err != nil {
		return nil, err
	}

	key := s.keys[pt.Header.Kid]
	if key == nil {
		return &pt.Claims, KeyNotFoundError
	}

	verifier, haveVerifier := jwsVerifiers[pt.Header.Alg]
	if !haveVerifier {
		return &pt.Claims, AlgorithmNotSupportedError
	}

	return &pt.Claims, verifier.verify(&pt, key, verifier.hash)
}
