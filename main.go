package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bvantagelimited/freeradius_exporter/client"
	"github.com/bvantagelimited/freeradius_exporter/collector"
)

var version, commit, date string

func main() {
	fs := flag.NewFlagSet("freeradius_exporter", flag.ContinueOnError)
	appHelp := fs.Bool("help", false, "Display help")
	appVersion := fs.Bool("version", false, "Display version information")
	_ = fs.String("config", "", "Config file (optional)")

	listenAddr := fs.String("web.listen-address", ":9812", "Address to listen on for web interface and telemetry.")
	metricsPath := fs.String("web.telemetry-path", "/metrics", "A path under which to expose metrics.")
	metricsAuthToken := fs.String("web.auth-token", "", "Auth token required in X-Auth-Token header to access /metrics (optional).")
	metricsAllowedIPs := fs.String("web.allowed-ips", "", "Comma-separated list of IPs or CIDR ranges allowed to access /metrics (optional).")
	radiusTimeout := fs.Int("radius.timeout", 5000, "Timeout, in milliseconds [RADIUS_TIMEOUT].")
	radiusAddr := fs.String("radius.address", "127.0.0.1:18121", "Address of FreeRADIUS status server [RADIUS_ADDRESS].")
	homeServers := fs.String("radius.homeservers", "", "List of FreeRADIUS home servers to check, e.g. '172.28.1.2:1812:auth,172.28.1.3:1813:acct' [RADIUS_HOMESERVERS].")
	radiusSecret := fs.String("radius.secret", "adminsecret", "FreeRADIUS client secret [RADIUS_SECRET].")

	err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarNoPrefix(), ff.WithConfigFileFlag("config"), ff.WithConfigFileParser(ff.JSONParser))
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	if *appHelp {
		fs.PrintDefaults()
		os.Exit(0)
	}

	if *appVersion {
		println(filepath.Base(os.Args[0]), version, commit, date)
		os.Exit(0)
	}

	allowedCIDRs, err := parseAllowedIPs(*metricsAllowedIPs)
	if err != nil {
		println(err)
		os.Exit(1)
	}

	registry := prometheus.NewRegistry()

	hs := strings.Split(*homeServers, ",")

	radiusClient, err := client.NewFreeRADIUSClient(*radiusAddr, hs, *radiusSecret, *radiusTimeout)
	if err != nil {
		log.Fatal(err)
	}

	registry.MustRegister(collector.NewFreeRADIUSCollector(radiusClient))

	metricsHandler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle(*metricsPath, withTokenOrIP(*metricsAuthToken, allowedCIDRs, metricsHandler))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>FreeRADIUS Exporter</title></head>
			<body>
			<h1>FreeRADIUS Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})

	srv := &http.Server{}
	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Providing metrics at %s%s", *listenAddr, *metricsPath)
	log.Fatal(srv.Serve(listener))
}

func parseAllowedIPs(input string) ([]*net.IPNet, error) {
	if input == "" {
		return nil, nil
	}
	entries := strings.Split(input, ",")
	var result []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if ip := net.ParseIP(entry); ip != nil {
			if ip.To4() != nil {
				result = append(result, &net.IPNet{
					IP:   ip.To4(),
					Mask: net.CIDRMask(32, 32),
				})
			} else {
				result = append(result, &net.IPNet{
					IP:   ip.To16(),
					Mask: net.CIDRMask(128, 128),
				})
			}

			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			result = append(result, cidr)
			continue
		}
		return nil, fmt.Errorf("Invalid IP or CIDR : %s", entry)
	}
	return result, nil
}

func withTokenOrIP(token string, allowed []*net.IPNet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no filters defined → PASS
		if token == "" && len(allowed) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// token valid → PASS
		if token != "" && r.Header.Get("X-Auth-Token") == token {
			next.ServeHTTP(w, r)
			return
		}

		// valid CIDR or IP → PASS
		if len(allowed) > 0 {
			ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				ip := net.ParseIP(ipStr)
				for _, ipNet := range allowed {
					if ipNet.Contains(ip) {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
		}

		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}
