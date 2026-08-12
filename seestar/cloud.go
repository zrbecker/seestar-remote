package seestar

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/zrbecker/seestar-remote/internal/tnauth"
	"github.com/zrbecker/seestar-remote/kalay"
)

// ConnectConfig configures cloud authorization and the Kalay tunnel to a device port.
type ConnectConfig struct {
	Email, Password   string
	Token             string // optional pre-obtained access token (skips Login)
	DeviceModel       string // e.g. "Seestar S30 Pro"
	DeviceSn          string // device short serial
	Master            string // rendezvous master "host:port"
	ClientHelloRecord []byte // DTLS ClientHello record to replay
	AppVersion        string // x-params app_version (default "3.3.0")
}

// remoteConnectData is the online-link response. The UID and password rotate per call.
type remoteConnectData struct {
	ConID         string `json:"conId"`
	DeviceUID     string `json:"deviceUid"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	P2PLicenseKey string `json:"p2pLicenseKey"`
	SDKLicenseKey string `json:"sdkLicenseKey"`
	P2PStatus     int    `json:"p2pStatus"`
}

// Login exchanges email/password for a Seestar cloud access token.
func Login(email, password string) (string, error) {
	body, err := json.Marshal(map[string]string{"authKey": email, "password": password, "authType": "email"})
	if err != nil {
		return "", fmt.Errorf("login: marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", "https://api.seestar.com/v1/user/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("login: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-service-platform", "seestar")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("login http %d: read body: %w", resp.StatusCode, err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("login http %d: malformed response: %w: %s", resp.StatusCode, err, string(b))
	}
	if out.Data.AccessToken == "" {
		return "", fmt.Errorf("login http %d: %s", resp.StatusCode, string(b))
	}
	return out.Data.AccessToken, nil
}

func randUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// onlineLink authorizes a fresh connection window and returns the current credentials.
func onlineLink(token, model, sn, appVer string) (remoteConnectData, int, error) {
	u := "https://api-ithings.zwoastro.com/v1/device-p2p/online-link?deviceModel=" +
		url.QueryEscape(model) + "&deviceSn=" + url.QueryEscape(sn) + "&srcId=" + randUUID()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return remoteConnectData{}, 0, fmt.Errorf("online-link: build request: %w", err)
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("x-service-platform", "seestar")
	req.Header.Set("x-lang", "en")
	// The API rejects clients that do not identify as the iOS app.
	req.Header.Set("x-params", `{"app_version":"`+appVer+`","country_code":"US","model":"iPad Pro (12.9 inch, 3rd generation)","channel":"appstore","os_version":"26.5","platform":"iOS"}`)
	req.Header.Set("User-Agent", "Seestar/"+appVer+" (iPad; iOS 26.5; Scale/2.00)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return remoteConnectData{}, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return remoteConnectData{}, resp.StatusCode, fmt.Errorf("online-link http %d: read body: %w", resp.StatusCode, err)
	}
	var out struct {
		Data remoteConnectData `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return remoteConnectData{}, resp.StatusCode, fmt.Errorf("online-link http %d: malformed response: %w: %s", resp.StatusCode, err, string(b))
	}
	return out.Data, resp.StatusCode, nil
}

// reportEvent posts a p2p connection lifecycle event. Failures are ignored.
func reportEvent(token, conID, model, sn, event string) {
	body := fmt.Sprintf(`{"conId":"%s","deviceModel":"%s","deviceSn":"%s","event":"%s"}`, conID, model, sn, event)
	req, err := http.NewRequest("POST", "https://api-ithings.zwoastro.com/v1/device-log/report", bytes.NewReader([]byte(body)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[seestar] report-event %s: build request: %v\n", event, err)
		return
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("x-service-platform", "seestar")
	req.Header.Set("x-lang", "en")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

// Dial authorizes with the cloud and opens a Kalay tunnel to a device-local port. The device
// accepts only one remote session at a time; online-link returns HTTP 400 while it is busy.
func Dial(cfg ConnectConfig, port int) (*kalay.Tunnel, error) {
	if cfg.AppVersion == "" {
		cfg.AppVersion = "3.3.0"
	}
	token := cfg.Token
	if token == "" {
		t, err := Login(cfg.Email, cfg.Password)
		if err != nil {
			return nil, err
		}
		token = t
	}
	link, status, err := onlineLink(token, cfg.DeviceModel, cfg.DeviceSn, cfg.AppVersion)
	if err != nil {
		return nil, fmt.Errorf("online-link: %w", err)
	}
	if link.DeviceUID == "" || link.Password == "" {
		return nil, fmt.Errorf("online-link http %d: no creds (device busy?)", status)
	}
	reportEvent(token, link.ConID, cfg.DeviceModel, cfg.DeviceSn, "p2pConnectStart")

	authKey, err := tnauth.DeriveAuthKey(link.SDKLicenseKey)
	if err != nil {
		return nil, fmt.Errorf("derive authkey: %w", err)
	}
	psk := sha256.Sum256([]byte(link.Password))
	return kalay.OpenTunnel(kalay.TunnelConfig{
		Master:            cfg.Master,
		PSK:               psk[:],
		Identity:          []byte(link.Username),
		ClientHelloRecord: cfg.ClientHelloRecord,
		Port:              port,
		Device: kalay.DeviceIdentity{
			UID:     link.DeviceUID,
			Sn:      cfg.DeviceSn,
			ConID:   link.ConID,
			AuthKey: authKey,
		},
	})
}
