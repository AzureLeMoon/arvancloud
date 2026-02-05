package main

import (
	"testing"

	"github.com/libdns/arvancloud"
	"github.com/libdns/libdns/libdnstest"
)

func TestArvancloudProvider(t *testing.T) {
	apiToken := "2fcff0d4-8410-5f83-9355-1ef2e5ced509"
	testZone := "netetkharabe.ir."

	if apiToken == "" || testZone == "" {
		t.Skip("Skipping Cloudflare provider tests: ARVANCLOUD_API_KEY and/or ARVANCLOUD_TEST_ZONE environment variables must be set")
	}


	provider := &arvancloud.Provider{
		AuthAPIKey:  apiToken,
	}

	suite := libdnstest.NewTestSuite(provider, testZone)
	suite.SkipRRTypes = map[string]bool{"SVCB": true, "HTTPS": true}
	suite.RunTests(t)
}