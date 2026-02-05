package main

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/arvancloud" // Ensure this matches the module name in your go.mod
	"github.com/libdns/libdns"
)

func main() {
	token := "2fcff0d4-8410-5f83-9355-1ef2e5ced509"
	zone := "netetkharabe.ir"

	if token == "" || zone == "" {
		fmt.Println("Error: Please set ARVANCLOUD_API_KEY and ARVANCLOUD_ZONE environment variables.")
		return
	}

	p := &arvancloud.Provider{
		AuthAPIKey: token,
	}

	ctx := context.Background()

	// 1. List Records
	fmt.Printf("Listing records for zone: %s\n", zone)
	records, err := p.GetRecords(ctx, zone)
	if err != nil {
		panic(fmt.Errorf("GetRecords failed: %w", err))
	}

	for _, r := range records {
		fmt.Printf("- [%s] %s : %s\n", r.RR().Type, r.RR().Name, r.RR().Data)
	}

	// 2. Create a Test Record
	testName := fmt.Sprintf("test-%d", time.Now().Unix())
	fmt.Printf("\nCreating TXT record: %s...\n", testName)
	newRec := libdns.TXT{
		Name:  testName,
		Text: "manual-test-run",
		TTL:   time.Minute * 2,
	}

	added, err := p.AppendRecords(ctx, zone, []libdns.Record{newRec})
	if err != nil {
		panic(fmt.Errorf("AppendRecords failed: %w", err))
	}
	fmt.Printf("Successfully created: %+v\n", added)
}
