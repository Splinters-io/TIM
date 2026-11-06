// Command tim-device simulates a "time-locked" device: one that validates a
// server's TLS certificate against a clock it learned from the network.
//
// With a correct clock it rejects the testbed's expired certificate and is
// stuck. Pointed at TIM as its time source, it learns a date inside the
// certificate's validity window and connects to its OWN real server. It does
// not bypass validation — it still checks the real certificate against the
// real CA; only the clock changes. That is exactly the repair TIM performs.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	server := env("SERVER", "https://server:8443/")
	caFile := env("CA", "/certs/ca.pem")
	source := env("TIME_SOURCE", "real")
	serverName := env("SERVER_NAME", "")
	httpHost := env("HTTP_HOST", "")

	now, how, err := resolveTime(source, httpHost)
	if err != nil {
		fmt.Printf("DEVICE: cannot get time from %q: %v\n", source, err)
		os.Exit(2)
	}
	fmt.Printf("DEVICE: time source %s -> clock is %s (%s)\n", source, now.UTC().Format(time.RFC3339), how)

	pool := x509.NewCertPool()
	if pem, err := os.ReadFile(caFile); err == nil {
		pool.AppendCertsFromPEM(pem)
	} else {
		fmt.Printf("DEVICE: warning: cannot read CA %s: %v\n", caFile, err)
	}

	conf := &tls.Config{
		RootCAs: pool,
		// This is the whole trick: the device verifies the certificate as of
		// the time it believes it is, not the real time.
		Time: func() time.Time { return now },
	}
	if serverName != "" {
		conf.ServerName = serverName
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: conf},
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(server)
	if err != nil {
		fmt.Printf("DEVICE STUCK: TLS to %s failed at clock %s:\n  %v\n", server, now.UTC().Format(time.RFC3339), err)
		if strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "not yet valid") {
			fmt.Println("  -> This is the time-lock. Point TIME_SOURCE at TIM to fix the clock.")
		}
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	fmt.Printf("DEVICE WORKING: %s accepted the real certificate at clock %s\n", server, now.UTC().Format(time.RFC3339))
	fmt.Printf("  server said: %s\n", strings.TrimSpace(string(body)))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// resolveTime gets the current time the way the device would.
func resolveTime(source, httpHost string) (time.Time, string, error) {
	switch {
	case source == "real":
		return time.Now(), "real system clock", nil
	case strings.HasPrefix(source, "ntp://"):
		return ntpTime(strings.TrimPrefix(source, "ntp://"))
	case strings.HasPrefix(source, "http://"), strings.HasPrefix(source, "https://"):
		return httpDate(source, httpHost)
	}
	return time.Time{}, "", fmt.Errorf("unknown time source (use real, ntp://host[:port], or http://host/)")
}

const ntpEpochOffset = 2208988800

func ntpTime(hostport string) (time.Time, string, error) {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "123")
	}
	conn, err := net.DialTimeout("udp", hostport, 5*time.Second)
	if err != nil {
		return time.Time{}, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	if _, err := conn.Write(req); err != nil {
		return time.Time{}, "", err
	}
	resp := make([]byte, 48)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return time.Time{}, "", err
	}
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	t := time.Unix(int64(secs)-ntpEpochOffset, int64(frac)*1e9>>32).UTC()
	return t, "NTP", nil
}

func httpDate(url, host string) (time.Time, string, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return time.Time{}, "", err
	}
	if host != "" {
		req.Host = host // the upstream the TIM proxy should fetch
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return time.Time{}, "", err
	}
	resp.Body.Close()
	d := resp.Header.Get("Date")
	if d == "" {
		return time.Time{}, "", fmt.Errorf("no Date header in response")
	}
	t, err := http.ParseTime(d)
	if err != nil {
		return time.Time{}, "", err
	}
	return t.UTC(), "HTTP Date header", nil
}
