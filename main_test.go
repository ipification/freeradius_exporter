package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestWithTokenOrIP(t *testing.T) {
	allowedCIDRs, err := parseAllowedIPs("192.168.1.0/24,10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error in test setup: %v", err)
	}
	validToken := "secret-token"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	protected := withTokenOrIP(validToken, allowedCIDRs, handler)

	tests := []struct {
		name       string
		remoteAddr string
		authToken  string
		wantCode   int
	}{
		{"Valid IP match subnet", "192.168.1.42:1234", "", http.StatusOK},
		{"Valid IP exact match", "10.0.0.1:9999", "", http.StatusOK},
		{"Valid token", "8.8.8.8:1111", "secret-token", http.StatusOK},
		{"Invalid IP and token", "8.8.8.8:1111", "wrong-token", http.StatusForbidden},
		{"No auth at all", "8.8.8.8:1111", "", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/metrics", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.authToken != "" {
				req.Header.Set("X-Auth-Token", tc.authToken)
			}

			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("Expected %d, got %d", tc.wantCode, rec.Code)
			}
		})
	}
}

func TestParseAllowedIPs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []*net.IPNet
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
			wantErr:  false,
		},
		{
			name:  "valid single IP",
			input: "192.168.1.10",
			expected: func() []*net.IPNet {
				_, ip, _ := net.ParseCIDR("192.168.1.10/32")
				return []*net.IPNet{
					ip,
				}
			}(),
			wantErr: false,
		},
		{
			name:  "valid CIDR",
			input: "10.0.0.0/8",
			expected: func() []*net.IPNet {
				_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
				return []*net.IPNet{cidr}
			}(),
			wantErr: false,
		},
		{
			name:  "valid mix IP and CIDR",
			input: "192.168.1.1,10.0.0.0/24",
			expected: func() []*net.IPNet {
				_, ip, _ := net.ParseCIDR("192.168.1.1/32")
				_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
				return []*net.IPNet{
					ip,
					cidr,
				}
			}(),
			wantErr: false,
		},
		{
			name:  "valid ipv6",
			input: "2001:db8::1",
			expected: func() []*net.IPNet {
				return []*net.IPNet{
					{
						IP:   net.ParseIP("2001:db8::1"),
						Mask: net.CIDRMask(128, 128),
					},
				}
			}(),
			wantErr: false,
		},
		{
			name:  "valid mix ipv6 IP and CIDR",
			input: "2001:db8::1,2001:db9::/56",
			expected: func() []*net.IPNet {
				_, ip, _ := net.ParseCIDR("2001:db8::1/128")
				_, cidr, _ := net.ParseCIDR("2001:db9::/56")
				return []*net.IPNet{
					ip,
					cidr,
				}
			}(),
			wantErr: false,
		},
		{
			name:  "valid mix ipv6 IP and CIDR",
			input: "2001:db8::1,2001:db9::/56,192.168.1.1,10.0.0.0/24",
			expected: func() []*net.IPNet {
				_, ip6, _ := net.ParseCIDR("2001:db8::1/128")
				_, cidr6, _ := net.ParseCIDR("2001:db9::/56")
				_, ip4, _ := net.ParseCIDR("192.168.1.1/32")
				_, cidr4, _ := net.ParseCIDR("10.0.0.0/24")
				return []*net.IPNet{
					ip6,
					cidr6,
					ip4,
					cidr4,
				}
			}(),
			wantErr: false,
		},
		{
			name:    "invalid entry",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			input:   "192.168.1.1,not-an-ip",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowedIPs(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error = %v, got = %v", tt.wantErr, err)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, got)
			}
		})
	}
}
