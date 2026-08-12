package seestar

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Device is one entry from the account's device list. The API also returns the device's
// stored location; those fields are omitted here.
type Device struct {
	Sn          string `json:"deviceSn"`
	Model       string `json:"deviceModel"`
	Alias       string `json:"deviceAlias"`
	SSID        string `json:"ssid"`
	Status      int    `json:"deviceStatus"`
	Shared      bool   `json:"isShared"`
	ShareStatus int    `json:"shareStatus"`
}

// Share states reported for a device.
const (
	shareNone     = 0 // owned, not shared with anyone
	shareOut      = 1 // owned, shared with another account
	shareReceived = 2 // owned by another account, shared with this one
)

// SharedWithMe reports whether the device belongs to another account.
func (d Device) SharedWithMe() bool { return d.ShareStatus == shareReceived }

// Label renders a device for a selection prompt.
func (d Device) Label() string {
	name := d.Alias
	if name == "" {
		name = d.SSID
	}
	if name == "" {
		name = d.Model
	}
	label := fmt.Sprintf("%s (%s, %s)", name, d.Sn, d.Model)
	if d.SharedWithMe() {
		label += " [shared with you]"
	}
	return label
}

// ListDevices returns the account's devices, including any shared with it by another
// account. Without isContainShared the API returns only owned devices.
func ListDevices(token, appVer string) ([]Device, error) {
	if appVer == "" {
		appVer = "3.3.0"
	}
	req, err := http.NewRequest("GET", "https://api-ithings.zwoastro.com/v1/my-device", nil)
	if err != nil {
		return nil, fmt.Errorf("my-device: build request: %w", err)
	}
	q := req.URL.Query()
	q.Set("current", "1")
	q.Set("pageSize", "100")
	q.Set("isContainShared", "1")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", token)
	req.Header.Set("x-service-platform", "seestar")
	req.Header.Set("x-lang", "en")
	// The API rejects clients that do not identify as the iOS app.
	req.Header.Set("x-params", `{"app_version":"`+appVer+`","country_code":"US","model":"iPad Pro (12.9 inch, 3rd generation)","channel":"appstore","os_version":"26.5","platform":"iOS"}`)
	req.Header.Set("User-Agent", "Seestar/"+appVer+" (iPad; iOS 26.5; Scale/2.00)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("my-device http %d: read body: %w", resp.StatusCode, err)
	}
	var out struct {
		Code int `json:"code"`
		Msg  string
		Data struct {
			Items []Device `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("my-device http %d: malformed response: %w: %s", resp.StatusCode, err, string(b))
	}
	if out.Code != 200 {
		return nil, fmt.Errorf("my-device http %d: code %d: %s", resp.StatusCode, out.Code, out.Msg)
	}
	return out.Data.Items, nil
}
