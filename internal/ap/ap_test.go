package ap

import (
	"strings"
	"testing"
)

func TestConfigs(t *testing.T) {
	c := Config{Iface: "wlan1", SSID: "TIM", Pass: "hunter2hunter2", Gateway: "10.77.0.1"}
	if err := validate(&c); err != nil {
		t.Fatal(err)
	}
	h := HostapdConf(c)
	for _, want := range []string{"interface=wlan1", "ssid=TIM", "channel=6", "hw_mode=g", "wpa_passphrase=hunter2hunter2"} {
		if !strings.Contains(h, want+"\n") {
			t.Errorf("hostapd.conf missing %q:\n%s", want, h)
		}
	}
	d := DnsmasqConf(c)
	for _, want := range []string{"interface=wlan1", "dhcp-range=10.77.0.10,10.77.0.200,255.255.255.0,12h", "dhcp-option=option:ntp-server,10.77.0.1", "dhcp-option=4,10.77.0.1"} {
		if !strings.Contains(d, want+"\n") {
			t.Errorf("dnsmasq.conf missing %q:\n%s", want, d)
		}
	}

	open := Config{Iface: "wlan1", SSID: "TIM", Gateway: "10.77.0.1", Channel: 36}
	validate(&open)
	if h := HostapdConf(open); strings.Contains(h, "wpa=") || !strings.Contains(h, "hw_mode=a") {
		t.Errorf("open 5GHz config wrong:\n%s", h)
	}
}

func TestValidate(t *testing.T) {
	bad := []Config{
		{Iface: "", SSID: "x", Gateway: "10.0.0.1"},
		{Iface: "w", SSID: "", Gateway: "10.0.0.1"},
		{Iface: "w", SSID: "x", Pass: "short", Gateway: "10.0.0.1"},
		{Iface: "w", SSID: "x\nbad=1", Gateway: "10.0.0.1"},
		{Iface: "w", SSID: "x", Gateway: "nope"},
	}
	for i, c := range bad {
		if err := validate(&c); err == nil {
			t.Errorf("case %d should fail", i)
		}
	}
}
