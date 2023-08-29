package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type key struct {
	key     []byte
	keyHex  string
	created time.Time
}

var currentKeyId = ""
var keys = map[string]key{}

var privateKey, privateKeyString, err = generate64ByteKey()
var signingKeyHex = "9fa4c01caa2c51f475316ce4485f40339b2d67cf358d7f7ca0ca013f6dc8a59b380ea73f7d8e0dfee04f14cf4168935f0a3493d2079cfbf2f164062af08d446f"

// var signingKeyHex = "094c816860ee7171bf1e8e955df82907f1abc63a2226bf3c7de252125885b41fbe273ab4a9a941ce5ca0199c186f1b681b88291e0935c15e7c8f8444b2f78fcd"
var signingKey, _ = convertHexKey(signingKeyHex)

// https://pkg.go.dev/github.com/golang-jwt/jwt/v5#example-New-Hmac
type CustomClaims struct {
	SessionID int64 `json:"sessionid"`
	jwt.RegisteredClaims
}

func (c CustomClaims) Validate() error {
	if c.SessionID != 12345 {
		return errors.New("must be 12345")
	}
	return nil
}

func main() {
	fmt.Println(privateKeyString)
	pass := "kdjfj9t949thih"

	hashPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	err = comparePassword(hashPass, pass)
	if err != nil {
		log.Fatalln("something went wrong")
	}

	log.Println("password match")

}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

func comparePassword(hashedPassword []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	return nil
}

func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("error in generatenewkey while generating key: %w", err)
	}

	uid := uuid.NewString()

	keys[uid] = key{
		key:     newKey,
		keyHex:  hex.EncodeToString(newKey),
		created: time.Now(),
	}

	currentKeyId = uid

	return nil
}

// TODO: need to move this out into a seperate applicaiton and reference the actual key as environment variable
func generate64ByteKey() ([]byte, string, error) {
	// Create a byte slice to hold the random bytes
	randomBytes := make([]byte, 64)

	// Read random bytes from the crypto/rand package
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, "", fmt.Errorf("error generating random bytes: %w", err)
	}

	keyString := hex.EncodeToString(randomBytes)

	return randomBytes, keyString, nil
}

func convertHexKey(k string) ([]byte, error) {
	result, err := hex.DecodeString(k)
	if err != nil {
		return nil, fmt.Errorf("error in converting key hex string to []byte: %w", err)
	}
	return result, nil
}

func signMessage(msg []byte) ([]byte, error) {
	// key for sha512 is 64 bytes
	h := hmac.New(sha512.New, privateKey)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("error in signmessage while hashing: %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSignature(msg, signature []byte) (bool, error) {
	newSignature, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("error verifyinig signature: %w", err)
	}
	same := hmac.Equal(newSignature, signature)
	return same, nil
}

func createToken(c *CustomClaims) (string, error) {

	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(keys[currentKeyId])
	if err != nil {
		return "", fmt.Errorf("error in createtoken when signing token: %w", err)
	}
	return signedToken, nil
}

func parseToken(signedToken string) (*CustomClaims, error) {
	t, err := jwt.ParseWithClaims(signedToken, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("invalid signing algorithm; expected %s, got %s", jwt.SigningMethodHS512.Alg(), t.Method.Alg())
		}
		// could also check the keyid here to find the correct key if multiple are used
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key id")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("invalid key id")
		}

		return k.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error in parse token while parsing token: %w", err)
	}
	if t == nil || !t.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return t.Claims.(*CustomClaims), nil
}
