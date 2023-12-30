package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/cors"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/otakakot/sample-go-webauthn-passkey/internal/api"
)

func main() {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  "localhost",
		RPDisplayName:         "passkey",
		RPOrigins:             []string{"http://localhost:5500"},
		AttestationPreference: protocol.PreferDirectAttestation,
	})
	if err != nil {
		panic(err)
	}

	key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	hdl, err := api.NewServer(&Handler{
		webAuthn: wa,
		block:    block,
	})
	if err != nil {
		panic(err)
	}

	options := cors.Options{
		AllowedOrigins: []string{"http://*"},
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: cors.New(options).Handler(hdl),
	}

	slog.Info("Listening on http://localhost:8080")

	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}

var _ webauthn.User = (*User)(nil)

type User struct {
	ID string
}

// WebAuthnCredentials implements webauthn.User.
func (us *User) WebAuthnCredentials() []webauthn.Credential {
	return nil
}

// WebAuthnDisplayName implements webauthn.User.
func (us *User) WebAuthnDisplayName() string {
	return ""
}

// WebAuthnID implements webauthn.User.
func (us *User) WebAuthnID() []byte {
	return []byte(us.ID)
}

// WebAuthnIcon implements webauthn.User.
func (us *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnName implements webauthn.User.
func (us *User) WebAuthnName() string {
	return ""
}

var _ api.Handler = (*Handler)(nil)

type Handler struct {
	webAuthn *webauthn.WebAuthn
	block    cipher.Block
}

// InitializeAttestation implements api.Handler.
func (hdl *Handler) InitializeAttestation(ctx context.Context) (api.InitializeAttestationRes, error) {
	options, session, err := hdl.webAuthn.BeginRegistration(&User{
		ID: "passkey",
	})
	if err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to begin registration. error: %s", err),
		}, nil
	}

	var buf bytes.Buffer

	enc := msgpack.NewEncoder(&buf)

	enc.SetCustomStructTag("json")

	if err := enc.Encode(options.Response); err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to encode credential creation options. error: %s", err),
		}, err
	}

	jsonSession, err := json.Marshal(session)
	if err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to marshal session. error: %s", err),
		}, err
	}

	// NOTE: セッションを Redis なりに保存してキーを cookie に設定すべきかも
	// NOTE: キャッシュを実装するのがめんどくさかったので暗号化してそのまま連れ回す
	// NOTE: セッションが漏れても問題ないものであるならば不要な暗号化
	// TODO: セッションって流出して問題ないのか確認する

	// NOTE: セッションを暗号化して cookie に保存

	cipherSession := make([]byte, aes.BlockSize+len(jsonSession))

	iv := cipherSession[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to read random. error: %s", err),
		}, nil
	}

	encryptStream := cipher.NewCTR(hdl.block, iv)

	encryptStream.XORKeyStream(cipherSession[aes.BlockSize:], jsonSession)

	cookie := http.Cookie{
		Name:     "session",
		Value:    base64.StdEncoding.EncodeToString(cipherSession),
		Path:     "/",
		Domain:   "",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   0,
	}

	return &api.InitializeAttestationOKHeaders{
		SetCookie: api.NewOptString(cookie.String()),
		Response: api.InitializeAttestationOK{
			Data: &buf,
		},
	}, nil
}

// FinalizeAttestation implements api.Handler.
func (hdl *Handler) FinalizeAttestation(ctx context.Context, req api.FinalizeAttestationReq, params api.FinalizeAttestationParams) (api.FinalizeAttestationRes, error) {
	// NOTE: セッションを無効にするための cookie
	cookie := http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}

	// NOTE: MessagePack 使いたかったけど挫折 ...
	// NOTE: JavaScript 側から MessagePack 形式で送信することができなかった ...

	data, err := protocol.ParseCredentialCreationResponseBody(req.Data)
	if err != nil {
		return &api.ErrorResponseHeaders{
			SetCookie: api.NewOptString(cookie.String()),
			Response: api.ErrorResponse{
				Message: fmt.Sprintf("failed to parse credential creation. error: %s", err),
			},
		}, nil
	}

	dec, err := base64.StdEncoding.DecodeString(params.Session)
	if err != nil {
		return &api.ErrorResponseHeaders{
			SetCookie: api.NewOptString(cookie.String()),
			Response: api.ErrorResponse{
				Message: fmt.Sprintf("failed to base64 decode. error: %s", err),
			},
		}, nil
	}

	// NOTE: cookie に保存されているセッションを復号化(復号)

	decryptedSession := make([]byte, len(dec[aes.BlockSize:]))

	decryptStream := cipher.NewCTR(hdl.block, dec[:aes.BlockSize])

	decryptStream.XORKeyStream(decryptedSession, dec[aes.BlockSize:])

	var session webauthn.SessionData

	if err := json.Unmarshal(decryptedSession, &session); err != nil {
		return &api.ErrorResponseHeaders{
			SetCookie: api.NewOptString(cookie.String()),
			Response: api.ErrorResponse{
				Message: fmt.Sprintf("failed to unmarshal session. error: %s", err),
			},
		}, nil
	}

	cred, err := hdl.webAuthn.CreateCredential(&User{ID: "passkey"}, session, data)
	if err != nil {
		return &api.ErrorResponseHeaders{
			SetCookie: api.NewOptString(cookie.String()),
			Response: api.ErrorResponse{
				Message: fmt.Sprintf("failed to create credential. error: %s", err),
			},
		}, nil
	}

	// FIXME: ここでクレデンシャルを保存する

	slog.Info(fmt.Sprintf("credential id: %+v", cred))

	return &api.FinalizeAttestationOK{
		SetCookie: api.NewOptString(cookie.String()),
	}, nil
}

// InitializeAssertion implements api.Handler.
func (hdl *Handler) InitializeAssertion(ctx context.Context) (api.InitializeAssertionRes, error) {
	panic("unimplemented")
}

// FinalizeAssertion implements api.Handler.
func (hdl *Handler) FinalizeAssertion(ctx context.Context, req api.OptFinalizeAssertionRequest) (api.FinalizeAssertionRes, error) {
	panic("unimplemented")
}

// InitializeAttestationJSON implements api.Handler.
func (hdl *Handler) InitializeAttestationJSON(ctx context.Context) (api.InitializeAttestationJSONRes, error) {
	options, session, err := hdl.webAuthn.BeginRegistration(&User{
		ID: "passkey",
	})
	if err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to begin registration. error: %s", err),
		}, nil
	}

	body, err := json.Marshal(options.Response)
	if err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to marshal credential creation options. error: %s", err),
		}, nil
	}

	jsonSession, err := json.Marshal(session)
	if err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to marshal session. error: %s", err),
		}, err
	}

	cipherSession := make([]byte, aes.BlockSize+len(jsonSession))

	iv := cipherSession[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return &api.ErrorResponse{
			Message: fmt.Sprintf("failed to read random. error: %s", err),
		}, nil
	}

	encryptStream := cipher.NewCTR(hdl.block, iv)

	encryptStream.XORKeyStream(cipherSession[aes.BlockSize:], jsonSession)

	cookie := http.Cookie{
		Name:     "session",
		Value:    base64.StdEncoding.EncodeToString(cipherSession),
		Path:     "/",
		Domain:   "",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   0,
	}

	return &api.InitializeAttestationJSONOKHeaders{
		SetCookie: api.NewOptString(cookie.String()),
		Response: api.InitializeAttestationJSONOK{
			Data: bytes.NewReader(body),
		},
	}, nil
}
