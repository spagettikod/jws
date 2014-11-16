package jws

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Token to be tested
type Token struct {
	UserID    int64 `json:"sub"`
	CreatedAt int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

var key = "abcd"

// String method to validate one token is the same as the other and give it a nice output format in JSON
func (t Token) String() string {
	jsonstr, err := json.Marshal(t)
	if err != nil {
		return err.Error()
	}
	return string(jsonstr)
}

// Create and initializa a new token
func NewToken(userID int64) (token *Token, err error) {
	token = new(Token)
	token.UserID = userID
	token.CreatedAt = time.Now().Unix()
	expstr := os.Getenv("tokenExpiration")
	if expstr == "" {
		err = errors.New("token expiration: environment parameter 'tokenExpiration' (in minutes) not set")
		return
	}
	exp, err := strconv.Atoi(expstr)
	if err != nil {
		return
	}
	token.ExpiresAt = time.Now().Unix() + int64(exp*60)
	return
}

func TestJws(t *testing.T) {
	os.Setenv("tokenExpiration", "20160")
	token, err := NewToken(23)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	t.Log("token1: " + token.String())
	encTok, err := Encode(key, token)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	decodedToken := new(Token)
	err = Decode(key, encTok, decodedToken)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	t.Log("token2: " + decodedToken.String())
	if token.String() != decodedToken.String() {
		t.Fail()
		return
	}
}

func TestJwsInvalidKey(t *testing.T) {
	os.Setenv("tokenExpiration", "20160")
	token, err := NewToken(23)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	encTok, err := Encode(key, token)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// Change the encyption key, this should make it impossible to authenticate the JWS
	err = Decode("efgh", encTok, token)
	if err == nil {
		t.Fail()
		return
	}
	if !strings.Contains(err.Error(), "jws signature:") {
		t.Fail()
		return
	}
}
