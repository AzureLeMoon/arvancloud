package arvancloud

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"github.com/libdns/libdns"
)

type arDomain struct {
	ID                  string    `json:"id"`
	AccountID			string	  `json:"account_id"`
	UserID				string	  `json:"user_id"`
	Domain              string    `json:"domain"`
	Name                string    `json:"name"`
	PlanLevel        	int 	  `json:"plan_level"`
	NSKeys				[]string  `json:"ns_keys"`
	SmartRoutingStatus  string    `json:"smart_routing_status"`
	CurrentNs			[]string  `json:"current_ns"`
	Status      		string    `json:"status"`
	Restriction 		[]string  `json:"restriction"`
	Type        		string    `json:"type"`
	CNAMETarget         string    `json:"cname_target"`
	CustomCNAME         string    `json:"custom_cname"`	
	UseNewWAfEngine 	bool      `json:"use_new_waf_engine"`
	Transfer 			struct {
		Domain 		string    `json:"domain"`
		AccountId	string	  `json:"account_id"`
		AccountName	string	  `json:"account_name"`
		OwnerId		string	  `json:"owner_id"`
		OwnerName	string	  `json:"owner_name"`
		Time        time.Time `json:"time"`
		Incoming 	bool      `json:"Incoming"`
	}
	FingerPrintStatus 	bool      `json:"fingerprint_status"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type arDNSRecord struct {
	ID            string      `json:"id,omitempty"`
	Type          string      `json:"type"`
	Name          string      `json:"name"`
	Value         any 		  `json:"value"` 
	TTL           int         `json:"ttl"`
	Cloud         bool        `json:"cloud"`
	IsProtected	  bool 		  `json:"is_protected,omitempty"`
	UpstreamHTTPS string      `json:"upstream_https,omitempty"`
	IPFilterMode  *IPFilter   `json:"ip_filter_mode,omitempty"`
}

// IPFilter defines the IP filtering mode for a record.
type IPFilter struct {
	Count     string `json:"count"`
	GeoFilter string `json:"geo_filter"`
	Order     string `json:"order"`
}

// ARecordValue represents the value structure for A and AAAA records.
// Note: The API expects a slice of these for A/AAAA records.
type ARecordValue struct {
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	Weight  int    `json:"weight,omitempty"`
	Country string `json:"country,omitempty"`
}

// TXTRecordValue represents the value structure for TXT records.
type TXTRecordValue struct {
	Text string `json:"text"`
}

// MXRecordValue represents the value structure for MX records.
type MXRecordValue struct {
	Host     string    `json:"host"`
	Priority uint16    `json:"priority"`
}

// CNAMERecordValue represents the value structure for CNAME  records.
type CNAMERecordValue struct {
	Host       string `json:"host"`
	HostHeader string `json:"host_header,omitempty"`
	Port       int    `json:"port,omitempty"`
}
// ANAMERecordValue represents the value structure for ANAME records.
type ANAMERecordValue struct{
	Location   string `json:"location"`
	HostHeader string `json:"host_header,omitempty"`
	Port       int    `json:"port,omitempty"`
}

// SRVRecordValue represents the value structure for SRV records.
type SRVRecordValue struct {
	Target   string    `json:"target"`
	Port     uint16    `json:"port"`
	Priority uint16    `json:"priority"`
	Weight   uint16    `json:"weight"`
}

// CAARecordValue represents the value structure for CAA records.
type CAARecordValue struct {
	Value string `json:"value"`
	Tag   string `json:"tag"`
}

// NSRecordValue represents the value structure for NS records.
type NSRecordValue struct {
	Host string `json:"host"`
}

// PTRRecordValue represents the value structure for PTR records.
type PTRRecordValue struct {
	Domain string `json:"domain"`
}

// TLSARecordValue represents the value structure for TLSA records.
type TLSARecordValue struct {
	Usage        string `json:"usage"`
	Selector     string `json:"selector"`
	MatchingType string `json:"matching_type"`
	Certificate  string `json:"certificate"`
}

func (r arDNSRecord) toLibDNSRecord(zone string) (libdns.Record, error) {
	name := libdns.RelativeName(r.Name, zone)
	ttl := time.Duration(r.TTL) * time.Second
	switch r.Type {
	case "A", "AAAA":
		addr, err := netip.ParseAddr(r.Value.(ARecordValue).IP)
		if err != nil {
			return libdns.Address{}, fmt.Errorf("invalid IP address %q: %v", r.Value.(ARecordValue).IP, err)
		}
		return libdns.Address{
			Name: name,
			TTL:  ttl,
			IP:   addr,
		}, nil
	case "CAA":
		return libdns.CAA{
			Name:  name,
			TTL:   ttl,
			Tag:   r.Value.(CAARecordValue).Tag,
			Value: r.Value.(CAARecordValue).Value,
		}, nil
	case "CNAME":
		return libdns.CNAME{
			Name:   name,
			TTL:    ttl,
			Target: r.Value.(CNAMERecordValue).Host,
		}, nil
	case "MX":
		return libdns.MX{
			Name:       name,
			TTL:        ttl,
			Preference: r.Value.(MXRecordValue).Priority,
			Target:     r.Value.(MXRecordValue).Host,
		}, nil
	case "NS":
		return libdns.NS{
			Name:   name,
			TTL:    ttl,
			Target: r.Value.(NSRecordValue).Host,
		}, nil
	case "SRV":		
		return  libdns.SRV{
			Name: name,
			TTL:  ttl,
			Priority: r.Value.(SRVRecordValue).Priority,
			Weight:   r.Value.(SRVRecordValue).Weight,
			Port:     r.Value.(SRVRecordValue).Port,
			Target:   r.Value.(SRVRecordValue).Target,
		}, nil
	case "TXT":
		// unwrap the quotes from the content
		unwrappedContent := unwrapContent(r.Value.(TXTRecordValue).Text)
		return libdns.TXT{
			Name: name,
			TTL:  ttl,
			Text: unwrappedContent,
		}, nil
	// 	fallthrough
	default:
		var fields map[string]any
		json.Unmarshal([]byte(r.Value.(string)), &fields)
		var vals []string
		for _, v := range fields {
				vals = append(vals, fmt.Sprintf("%v", v))
		}
		return libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: r.Type,
			Data: strings.Join(vals," "),
		}.Parse()
	}
}

func arvancloudRecord(r libdns.Record) (arDNSRecord, error) {

	rr := r.RR()
	arRec := arDNSRecord{
		// ID:   r.ID,
		Name:    rr.Name,
		Type:    rr.Type,
		TTL:     int(rr.TTL.Seconds()),
	}
	switch rec := r.(type) {
	case libdns.Address:
		arRec.Value = ARecordValue{
			IP: rec.IP.String(),
		}
	case libdns.CNAME:
		arRec.Value = CNAMERecordValue{
			Host: rec.Target,
		}
	case libdns.NS:
		arRec.Value = NSRecordValue{
			Host: rec.Target,
		}
	case libdns.CAA:
		arRec.Value = CAARecordValue{
			Tag:   rec.Tag,
			Value: rec.Value,
		}
	case libdns.MX:
		arRec.Value = MXRecordValue{
			Priority: rec.Preference,
			Host: rec.Target,
		}
	case libdns.SRV:
		arRec.Value = SRVRecordValue{
			Priority: rec.Priority,
			Weight:   rec.Weight,
			Port:     rec.Port,
			Target:   rec.Target,
		}
	case libdns.TXT:
		arRec.Value = TXTRecordValue{
			Text: wrapContent(rec.Text),
		}		
	}
	return arRec, nil
}

type arResponse struct {
	Data  	json.RawMessage `json:"data,omitempty"`
	Status	bool 			`json:"status,omitempty"`
	Errors  []string 	    `json:"errors,omitempty"`
	Message string          `json:"message,omitempty"`
	Links 	*arLinks 	    `json:"links,omitempty"`
	Meta 	*arMeta 		`json:"meta,omitempty"`
}

type arMeta struct {
	CurrentPage int `json:"current_page"`
	From        int `json:"from"`
	LastPage    int `json:"last_page"`
	Path        string `json:"path"`
	PerPage     int `json:"per_page"`
	To          int `json:"to"`
	Total       int `json:"total"`
}

type arLinks struct {
	First  string `json:"First"`
	Last   string `json:"Last"`
	Prev   string `json:"Prev"`
	Next   string `json:"Next"`
}