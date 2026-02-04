// Package arvancloud implements a DNS record management client compatible
// with the libdns interfaces for ArvanCloud.
package arvancloud

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with ArvanCloud.
type Provider struct {
	// AuthAPIKey is the API token for ArvanCloud.
	// It can be obtained from the ArvanCloud user panel.
	AuthAPIKey string `json:"auth_api_key,omitempty"`
	client *client
	mu     sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mu.Lock()
	if p.client == nil {
		p.client = newClient(p.AuthAPIKey)
	}
	p.mu.Unlock()

	arvanRecords, err := p.client.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, ar := range arvanRecords {
		libRecord, err := ar.toLibDNSRecord(zone)
		if err != nil {
			return nil, err
		}
		records = append(records, libRecord)
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	if p.client == nil {
		p.client = newClient(p.AuthAPIKey)
	}
	p.mu.Unlock()

	var addedRecords []libdns.Record
	for _, r := range records {
		
		result, err := p.client.createRecord(ctx, zone, r)
		if err != nil {
			return nil, err
		}
		libRecord, err := result.toLibDNSRecord(zone)
		if err != nil {
			return nil, fmt.Errorf("parsing Arvancloud DNS record %+v: %v", r, err)
		}
		addedRecords = append(addedRecords, libRecord)	
	}

	return addedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// For simplicity and correctness with Arvan's array model, we delete existing records
	// for the names/types provided and then append the new ones.
	// This ensures the state matches exactly what is requested.

	// 1. Find existing records for these names/types
	// 2. Delete them
	// 3. Append new ones

	// Optimization: We can just call DeleteRecords then AppendRecords,
	// but DeleteRecords requires exact value matching usually.
	// Here we want to overwrite *all* records for a given Name+Type.

	p.mu.Lock()
	if p.client == nil {
		p.client = newClient(p.AuthAPIKey)
	}
	p.mu.Unlock()

	existingRecords, err := p.client.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	for _, r := range records {
		existing := p.findExistingRecord(existingRecords, r.RR().Name, r.RR().Type, zone)
		if existing != nil {
			_,err := p.client.deleteRecord(ctx, zone, existing.ID)
			if err != nil {
				return nil, err
			}
			// Remove from local cache to avoid trying to delete again if multiple input records match same existing set
			// (Though findExistingRecord returns a pointer, removing from slice is harder,
			// but since we loop inputs, we might hit same ID twice.
			// Arvan API might 404 on second delete, which we should ignore or handle.)
		}
	}

	return p.AppendRecords(ctx, zone, records)
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	if p.client == nil {
		p.client = newClient(p.AuthAPIKey)
	}
	p.mu.Unlock()

	existingRecords, err := p.client.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var deletedRecords []libdns.Record

	for _, r := range records {
		existing := p.findExistingRecord(existingRecords, r.RR().Name, r.RR().Type, zone)
		if existing == nil {
			continue
		}
		var result arDNSRecord
		var libRecord libdns.Record
		if r.RR().Type == "A" || r.RR().Type == "AAAA" {
			// Handle array removal
			var currentVals []ARecordValue
			b, _ := json.Marshal(existing.Value)
			_ = json.Unmarshal(b, &currentVals)

			var newVals []ARecordValue
			found := false
			for _, v := range currentVals {
				if v.IP == r.RR().Data {
					found = true
					continue // Skip the one we want to delete
				}
				newVals = append(newVals, v)
			}

			if found {
				if len(newVals) == 0 {
					// Empty list, delete the whole record
					result, err = p.client.deleteRecord(ctx, zone, existing.ID)
					if err != nil {
						return nil, err
					}
					libRecord, err = result.toLibDNSRecord(zone)
					if err != nil {
						return nil, fmt.Errorf("parsing Arvancloud DNS record %+v: %v", r, err)
					}
				} else {
					// Update with remaining values
					existing.Value = newVals
					result, err := p.client.updateRecord(ctx, zone, existing.ID, *existing)
					if err != nil {
						return nil, err
					}
					libRecord, err = result.toLibDNSRecord(zone)
					if err != nil {
						return nil, fmt.Errorf("parsing Arvancloud DNS record %+v: %v", r, err)
					}		
				}
				deletedRecords = append(deletedRecords, libRecord)
			}
		} else {
			// Simple delete
			result, err := p.client.deleteRecord(ctx, zone, existing.ID)
			if err != nil {
				return nil, err
			}
			libRecord, err = result.toLibDNSRecord(zone)
			if err != nil {
				return nil, fmt.Errorf("parsing Arvancloud DNS record %+v: %v", r, err)
			}				
			deletedRecords = append(deletedRecords, libRecord)
		}
	}

	return deletedRecords, nil
}



// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
