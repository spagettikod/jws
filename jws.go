// Basic implementation of JSON Web Signature. It encodes and decodes base64 JWS strings into a struct using Go JSON marshalling.
// For further information about JWS see: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31
//
// See tests for examples.
package jws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Encodes and signs a payload struct. Payload is a struct that can be marshalled into JSON. The payload and header will be signed and encrypted with HMAC SHA256. Please note that this does not mean the actual payload in the JWS is encrypted. It's only base64 encoded.
func Encode(key string, payload interface{}) (jws string, err error) {
	var signatureParts []string
	// Get the JWS Header
	signatureParts = append(signatureParts, jwsHeader())

	// Get the payload which is the encoded Token
	var payloadStr string
	payloadStr, err = jwsPayload(payload)
	if err != nil {
		return
	}
	signatureParts = append(signatureParts, payloadStr)

	// Sign the unsigned signature using HMAC SHA256
	var signature string
	signature, err = sign(key, signatureParts[0], signatureParts[1])
	if err != nil {
		return
	}

	// Concatenate all parts of the JWS, base64 encoded header, payload and signature.
	signatureParts = append(signatureParts, signature)
	jws = strings.Join(signatureParts, ".")

	return
}

// Decode a JWS base64 encoded string. Payload content is unmarshalled into the supplied payload struct.
func Decode(key string, jws string, payload interface{}) error {
	var signatureParts []string

	// Split JWS into its three part, header, payload and signed signature
	signatureParts = strings.Split(jws, ".")
	if len(signatureParts) != 3 {
		return errors.New("jws: incomplete signature does not contain 3 parts, header, payload and signed signature")
	}

	// Sign the header and payload to get a signature we can validate
	signature, err := sign(key, signatureParts[0], signatureParts[1])
	if err != nil {
		return err
	}

	// Validate the generated signature is the same as the one in the recieved JWS
	if signature != signatureParts[2] {
		return errors.New("jws: signature authentication failed")
	}

	// Unmarshal the payload
	unmarshaledPayload, err := base64.StdEncoding.DecodeString(signatureParts[1])
	err = json.Unmarshal(unmarshaledPayload, payload)
	if err != nil {
		return err
	}

	return nil
}

func jwsHeader() string {
	json := "{\"alg\":\"HS256\"}"
	data := []byte(json)
	return base64.StdEncoding.EncodeToString(data)
}

func jwsPayload(v interface{}) (payload string, err error) {
	var jsonToken []byte
	jsonToken, err = json.Marshal(v)
	if err != nil {
		return
	}
	payload = base64.StdEncoding.EncodeToString(jsonToken)
	return
}

// Sign the base64 encoded header and payload by first concatenating them with a . inbetween.
func sign(key string, header string, payload string) (signed string, err error) {
	if key == "" {
		err = errors.New("jws: key can not be empty")
		return
	}

	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, []byte(key))
	_, err = mac.Write([]byte(unsigned))
	if err != nil {
		return
	}
	singedBytes := mac.Sum(nil)
	signed = base64.StdEncoding.EncodeToString(singedBytes)
	return
}
