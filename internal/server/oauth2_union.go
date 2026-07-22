package server

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
	"github.com/Lylighte/elementskin-union-svc/internal/session"
	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

const (
	oauth2AuthorizeScope = "account.read.self profile.read.owned"
	userInfoTokenTTL     = 600 * time.Second
)

func (s *Server) handleOAuth2GetSigPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.cfg.Union.EnableOAuth2 {
		writeOAuth2JSONError(w, http.StatusForbidden, "oauth2 not enabled")
		return
	}

	if origin := s.cfg.Union.CORSAllowOrigin; origin != "" {
		setOAuth2CORSHeaders(w, origin)
	}

	_, pubPEM, err := union.EnsureSigKeyPair(
		r.Context(),
		s.cfg.Union.OAuth2SigPrivateKeyPath,
		s.cfg.Union.OAuth2SigPublicKeyPath,
	)
	if err != nil {
		s.logger.Error("failed to ensure oauth2 signature key pair", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to load signature key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"signaturePublicKey": pubPEM})
}

func (s *Server) handleOAuth2Grant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.cfg.Union.EnableOAuth2 {
		writeOAuth2JSONError(w, http.StatusForbidden, "oauth2 not enabled")
		return
	}

	ctx := r.Context()
	sessionID := session.GetSessionCookie(r)
	if sessionID == "" {
		s.redirectToOAuthAuthorize(w, r)
		return
	}

	accessToken, err := s.sessionStore.Lookup(ctx, sessionID)
	if err != nil {
		s.logger.Error("failed to lookup session", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to lookup session")
		return
	}
	if accessToken == "" {
		s.redirectToOAuthAuthorize(w, r)
		return
	}

	esClient := bridge.NewElementSkinClient(s.cfg.Elementskin.BaseURL, s.httpClient)
	userInfo, err := esClient.GetUserInfo(ctx, accessToken)
	if err != nil {
		s.logger.Error("failed to get user info", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to get user info")
		return
	}

	privPEM, _, err := union.EnsureSigKeyPair(
		ctx,
		s.cfg.Union.OAuth2SigPrivateKeyPath,
		s.cfg.Union.OAuth2SigPublicKeyPath,
	)
	if err != nil {
		s.logger.Error("failed to ensure oauth2 signature key pair", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to load signature key")
		return
	}

	privKey, err := parseOAuth2RSAPrivateKey([]byte(privPEM))
	if err != nil {
		s.logger.Error("failed to parse oauth2 signature private key", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to parse signature key")
		return
	}

	hubPubPEM, err := s.unionClient.GetOAuth2BackendPublicKey(ctx)
	if err != nil {
		s.logger.Error("failed to fetch hub oauth2 public key", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to fetch hub public key")
		return
	}

	hubPubKey, err := parseOAuth2RSAPublicKey([]byte(hubPubPEM))
	if err != nil {
		s.logger.Error("failed to parse hub oauth2 public key", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to parse hub public key")
		return
	}

	memberKey := s.currentMemberKey(ctx)

	userInfoPayload, err := json.Marshal(map[string]any{
		"uid":        userInfo.ID,
		"nickname":   userInfo.DisplayName,
		"email":      userInfo.Email,
		"expires_at": time.Now().Unix() + int64(userInfoTokenTTL.Seconds()),
	})
	if err != nil {
		s.logger.Error("failed to marshal user info payload", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to build user info")
		return
	}

	userInfoB64 := base64.StdEncoding.EncodeToString(userInfoPayload)
	mac := hmacSHA256Hex(userInfoB64, memberKey)
	payloadToSign := userInfoB64 + "." + mac

	digest := sha256.Sum256([]byte(payloadToSign))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest[:])
	if err != nil {
		s.logger.Error("failed to sign user info token", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}

	tokenJSON, err := json.Marshal(map[string]string{
		"userInfo":  userInfoB64,
		"mac":       mac,
		"signature": base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		s.logger.Error("failed to marshal token json", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to build token")
		return
	}

	encrypted, err := rsaEncryptPKCS1v15Chunks(hubPubKey, tokenJSON)
	if err != nil {
		s.logger.Error("failed to encrypt user info token", "error", err)
		writeOAuth2JSONError(w, http.StatusInternalServerError, "failed to encrypt token")
		return
	}

	encryptedB64 := base64.StdEncoding.EncodeToString(encrypted)
	state := r.URL.Query().Get("state")

	redirectURL := s.cfg.Union.HubURL + "/oauth2/continue?userInfoToken=" +
		url.QueryEscape(encryptedB64) + "&state=" + url.QueryEscape(state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) redirectToOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	u := oAuthAuthorizeBase(s.cfg) + "/oauth/authorize?scope=" + oauth2AuthorizeScope +
		"&redirect_uri=" + url.QueryEscape(s.cfg.Elementskin.OAuth.RedirectURI)
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) currentMemberKey(ctx context.Context) string {
	settings := s.unionClient.SettingsStore()
	if settings != nil {
		if key, err := settings.Get(ctx, "member_key"); err == nil && key != "" {
			return key
		}
	}
	return s.cfg.Union.MemberKey
}

func writeOAuth2JSONError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func setOAuth2CORSHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
}

func hmacSHA256Hex(message, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	_, _ = h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func rsaEncryptPKCS1v15Chunks(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	chunkSize := pubKey.Size() - 11
	if chunkSize <= 0 {
		return nil, fmt.Errorf("invalid rsa key size")
	}

	var encrypted []byte
	for offset := 0; offset < len(plaintext); offset += chunkSize {
		end := offset + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext[offset:end])
		if err != nil {
			return nil, fmt.Errorf("encrypt chunk: %w", err)
		}
		encrypted = append(encrypted, chunk...)
	}
	return encrypted, nil
}

func parseOAuth2RSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs1 private key: %w", err)
	}
	return key, nil
}

func parseOAuth2RSAPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		return parsed, nil
	}

	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return pub, nil
}
