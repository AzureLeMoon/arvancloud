package arvancloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const (
	apiBaseURL = "https://napi.arvancloud.ir/cdn/4.0"
)

// client manages communication with the ArvanCloud API.
type client struct {
	AuthAPIKey string
	BaseURL      string
	httpClient   *http.Client
}

// newClient creates a new ArvanCloud API client.
func newClient(authKey string) *client {
	return &client{
		AuthAPIKey: authKey,
		BaseURL:      apiBaseURL,
		httpClient: &http.Client{
			Timeout: time.Second * 20,
		},
	}
}

type paginatedResponse struct {
	Data  []arDNSRecord `json:"data"`
	Links struct {
		Next *string `json:"next"`
	} `json:"links"`
	Meta struct {
		CurrentPage int `json:"current_page"`
		LastPage    int `json:"last_page"`
	} `json:"meta"`
}

type singleRecordResponse struct {
	Data    arDNSRecord `json:"data"`
	Message *string   `json:"message"`
}

// getRecords fetches DNS records for a zone.
func (c *client) getRecords(ctx context.Context, zone string) ([]arDNSRecord, error) {
	var records []arDNSRecord
	page := 1

	for {
		u := fmt.Sprintf("/domains/%s/dns-records?page=%d&per_page=100", zone, page)
		req, err := c.newRequest(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}

		var resp paginatedResponse
		if _,err := c.do(req, &resp); err != nil {
			return nil, err
		}

		records = append(records, resp.Data...)

		if resp.Links.Next == nil || resp.Meta.CurrentPage >= resp.Meta.LastPage {
			break
		}
		page++
	}

	return records, nil
}


func (p *Provider) findExistingRecord(records []arDNSRecord, name, rType, zone string) *arDNSRecord {
	searchName := libdns.AbsoluteName(name, zone)
	for i, r := range records {
		// Arvan name usually comes as "sub" or "sub.domain.com" depending on context,
		// but getRecords usually returns full name or relative?
		// The spec says "name" in response.
		// Let's assume absolute name matching or relative matching.
		// Safest is to compare both normalized absolute names.

		recordName := r.Name
		if !strings.Contains(recordName, zone) && recordName != "@" {
			// If record name is relative, make it absolute for comparison
			if recordName == "@" {
				recordName = zone
			} else {
				recordName = recordName + "." + zone
			}
		}
		recordName = strings.TrimSuffix(recordName, ".")

		if strings.EqualFold(recordName, searchName) && strings.EqualFold(r.Type, rType) {
			return &records[i]
		}
	}
	return nil
}
// createRecord creates a new DNS record.
func (c *client) createRecord(ctx context.Context, zone string, record libdns.Record) (arDNSRecord, error) {

	arRec, err := arvancloudRecord(record)
	if err != nil {
		return arDNSRecord{}, err
	}

	jsonBytes, err := json.Marshal(arRec)
	if err != nil {
		return arDNSRecord{}, err
	}

	u := fmt.Sprintf("/domains/%s/dns-records", zone)
	req, err := c.newRequest(ctx, http.MethodPost, u, bytes.NewReader(jsonBytes))
	if err != nil {
		return arDNSRecord{}, err
	}

	var resp arDNSRecord
	if _,err := c.do(req, &resp); err != nil {
		return arDNSRecord{}, err
	}

	return resp, nil
}

// deleteRecord deletes a DNS record.
func (c *client) deleteRecord(ctx context.Context, zone string, recordID string) (arDNSRecord, error) {
	u := fmt.Sprintf("/domains/%s/dns-records/%s", zone, recordID)
	req, err := c.newRequest(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return arDNSRecord{}, err
	}

	var resp arDNSRecord
	if _,err := c.do(req, &resp); err != nil {
		return arDNSRecord{}, err
	}

	return resp, nil
}

// updateRecord updates a DNS record.
func (c *client) updateRecord(ctx context.Context, zone string, recordID string, record arDNSRecord) (arDNSRecord, error) {
	u := fmt.Sprintf("/domains/%s/dns-records/%s", zone, recordID)
	req, err := c.newRequest(ctx, http.MethodPut, u, record)
	if err != nil {
		return arDNSRecord{}, err
	}

	var resp singleRecordResponse
	if _,err := c.do(req, &resp); err != nil {
		return arDNSRecord{}, err
	}

	return resp.Data, nil
}

func (c *client) do(req *http.Request, result any) (arResponse,error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return arResponse{}, err
	}
	defer resp.Body.Close()


	var respData arResponse

	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return arResponse{}, err
	}
	
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return arResponse{}, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	if len(respData.Errors) > 0 {
		return arResponse{}, fmt.Errorf("got errors: HTTP %d: %+v", resp.StatusCode, respData.Errors)
	}

	if len(respData.Data) > 0 && result != nil {
		err = json.Unmarshal(respData.Data, result)
		if err != nil {
			return arResponse{}, err
		}
	}
	return respData ,nil
}

func (c *client) newRequest(ctx context.Context, method, url string, payload any) (*http.Request, error) {
	var body []byte
	var err error

	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Apikey "+c.AuthAPIKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func unwrapContent(content string) string {
	if strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) {
		content = strings.TrimPrefix(strings.TrimSuffix(content, `"`), `"`)
	}
	return content
}

func wrapContent(content string) string {
	if !strings.HasPrefix(content, `"`) && !strings.HasSuffix(content, `"`) {
		content = fmt.Sprintf("%q", content)
	}
	return content
}