package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/urfave/cli"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const KEY1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJmg8rwO3n+2QAKmpvJE0ykFbZAS9gjUjviKMvVdvGqqoAoGCCqGSM49
AwEHoUQDQgAENlKjrC2WShZ1/Vge/NnnlI/AvyS4O8+Fe6FjD4ulZ/93IOZWWT3x
xedOeCC+KmElgOYRA1px0LNwA6gu5RaoZg==
-----END EC PRIVATE KEY-----`
const KEY1ID = "65289b19-e0c6-4918-8933-7961781adb0d"

const KEY2 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICYOKd/LySjKN7S0sbDiAxtWr7veMiBCZ42hRROCrRLLoAoGCCqGSM49
AwEHoUQDQgAEEawrkuYeV+Bjzab97rDIah46eCiYSJJ0lZIWd74OfJ+fpDJ5qpDV
W9fpgqUxZMbFG/H+pnT+a/6fZIWOGhr8OQ==
-----END EC PRIVATE KEY-----`
const KEY2ID = "eefdf879-c941-4701-bd5d-f357bff7798d"

func makeJwk(pemBlock, kid string) (jose.Signer, *jose.JSONWebKey, error) {

	var ecdsaPrivateKey *ecdsa.PrivateKey

	if pemBlock != "" {
		block, _ := pem.Decode([]byte(pemBlock))
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, nil, fmt.Errorf("failed to parse private key")
		}

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		ecdsaPrivateKey = key
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		ecdsaPrivateKey = key
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": kid},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ecdsaPrivateKey}, opts)
	if err != nil {
		return nil, nil, err
	}

	jwk := &jose.JSONWebKey{
		Key:       ecdsaPrivateKey.Public(),
		KeyID:     kid,
		Algorithm: "ES256",
		Use:       "sig",
	}

	if !jwk.Valid() {
		return nil, nil, errors.New("Invalid JWK")
	}

	return signer, jwk, nil

}

func makeJwt(
	signer jose.Signer,
	ID string,
	Subject string,
	Issuer string,
	Audience string) error {

	builder := jwt.Signed(signer)

	now := time.Now()

	claims := &jwt.Claims{
		ID:       ID,
		Subject:  Subject,
		Issuer:   Issuer,
		Audience: jwt.Audience{Audience},
		IssuedAt: jwt.NewNumericDate(now),
	}

	builder = builder.Claims(claims)

	jwtJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n\n", jwtJSON)

	jwtToken, err := builder.CompactSerialize()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n\n", jwtToken)

	return nil
}

func main() {
	app := cli.NewApp()

	app.Action = func(c *cli.Context) error {

		signer1, jwk1, err := makeJwk(KEY1, KEY1ID)
		if err != nil {
			return err
		}
		signer2, jwk2, err := makeJwk(KEY2, KEY2ID)
		if err != nil {
			return err
		}
		signer3, _, err := makeJwk("", uuid.NewV4().String())
		if err != nil {
			return err
		}

		jwks := &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{*jwk1, *jwk2},
		}

		jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println("// JWKS")
		fmt.Printf("%s\n\n", string(jwksJSON))

		fmt.Println("// Valid signature 1")
		err = makeJwt(signer1, "id1", "sub1", "iss1", "aud1")
		if err != nil {
			return err
		}

		fmt.Println("// Valid signature 2")
		err = makeJwt(signer2, "id2", "sub2", "iss1", "aud2")
		if err != nil {
			return err
		}

		fmt.Println("// Invalid signature")
		err = makeJwt(signer3, "id1", "sub1", "iss1", "aud1")
		if err != nil {
			return err
		}

		fmt.Println("// Invalid issuer")
		err = makeJwt(signer1, "id1", "sub1", "iss2", "aud1")
		if err != nil {
			return err
		}

		fmt.Println("// Invalid audience")
		err = makeJwt(signer1, "id1", "sub1", "iss1", "aud3")
		if err != nil {
			return err
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	}
}
