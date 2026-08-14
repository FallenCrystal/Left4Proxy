package discover

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ssdpMulticastAddr = "239.255.255.250:1900"
	ssdpDiscoverMsg   = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n\r\n"
)

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpDevice struct {
	DeviceType  string        `xml:"deviceType"`
	ServiceList []upnpService `xml:"serviceList>service"`
	DeviceList  []upnpDevice  `xml:"deviceList>device"`
}

type rootDevice struct {
	XMLName xml.Name   `xml:"root"`
	Device  upnpDevice `xml:"device"`
}

// UPnPMapper handles automatic UPnP-IGD port mapping on local gateway routers.
type UPnPMapper struct {
	controlURL  string
	serviceType string
	httpClient  *http.Client
}

// DiscoverUPnPGateway discovers the local UPnP Internet Gateway Device within a timeout.
func DiscoverUPnPGateway(ctx context.Context, timeout time.Duration) (*UPnPMapper, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.WriteToUDP([]byte(ssdpDiscoverMsg), udpAddr); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)

	client := &http.Client{Timeout: timeout}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		location := extractLocation(string(buf[:n]))
		if location == "" {
			continue
		}

		mapper, err := parseRootDesc(ctx, client, location)
		if err == nil && mapper != nil {
			return mapper, nil
		}
	}

	return nil, fmt.Errorf("no UPnP IGD gateway discovered")
}

func extractLocation(resp string) string {
	lines := strings.Split(resp, "\r\n")
	for _, l := range lines {
		lower := strings.ToLower(l)
		if strings.HasPrefix(lower, "location:") {
			return strings.TrimSpace(l[len("location:"):])
		}
	}
	return ""
}

func parseRootDesc(ctx context.Context, client *http.Client, locURL string) (*UPnPMapper, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", locURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var root rootDevice
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, err
	}

	srv := findWANConnectionService(&root.Device)
	if srv == nil {
		return nil, fmt.Errorf("no WAN connection service found in UPnP XML")
	}

	parsedLoc, err := url.Parse(locURL)
	if err != nil {
		return nil, err
	}

	ctrlURL, err := parsedLoc.Parse(srv.ControlURL)
	if err != nil {
		return nil, err
	}

	return &UPnPMapper{
		controlURL:  ctrlURL.String(),
		serviceType: srv.ServiceType,
		httpClient:  client,
	}, nil
}

func findWANConnectionService(dev *upnpDevice) *upnpService {
	for _, srv := range dev.ServiceList {
		if strings.Contains(srv.ServiceType, "WANIPConnection") || strings.Contains(srv.ServiceType, "WANPPPConnection") {
			return &srv
		}
	}
	for _, subDev := range dev.DeviceList {
		if srv := findWANConnectionService(&subDev); srv != nil {
			return srv
		}
	}
	return nil
}

// AddPortMapping requests a UDP port mapping from the gateway router.
func (m *UPnPMapper) AddPortMapping(ctx context.Context, externalPort, internalPort int, internalIP, description string) error {
	soapBody := fmt.Sprintf(
		`<?xml version="1.0"?>`+
			`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`+
			`<s:Body>`+
			`<u:AddPortMapping xmlns:u="%s">`+
			`<NewRemoteHost></NewRemoteHost>`+
			`<NewExternalPort>%d</NewExternalPort>`+
			`<NewProtocol>UDP</NewProtocol>`+
			`<NewInternalPort>%d</NewInternalPort>`+
			`<NewInternalClient>%s</NewInternalClient>`+
			`<NewEnabled>1</NewEnabled>`+
			`<NewPortMappingDescription>%s</NewPortMappingDescription>`+
			`<NewLeaseDuration>0</NewLeaseDuration>`+
			`</u:AddPortMapping>`+
			`</s:Body>`+
			`</s:Envelope>`,
		m.serviceType, externalPort, internalPort, internalIP, description,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", m.controlURL, bytes.NewBufferString(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#AddPortMapping"`, m.serviceType))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("UPnP AddPortMapping HTTP %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

// GetExternalIPAddress queries the router's external public IP address.
func (m *UPnPMapper) GetExternalIPAddress(ctx context.Context) (net.IP, error) {
	soapBody := fmt.Sprintf(
		`<?xml version="1.0"?>`+
			`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`+
			`<s:Body>`+
			`<u:GetExternalIPAddress xmlns:u="%s">`+
			`</u:GetExternalIPAddress>`+
			`</s:Body>`+
			`</s:Envelope>`,
		m.serviceType,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", m.controlURL, bytes.NewBufferString(soapBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#GetExternalIPAddress"`, m.serviceType))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type getExternalIPResp struct {
		IP string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	var ipResp getExternalIPResp
	if err := xml.Unmarshal(body, &ipResp); err != nil || ipResp.IP == "" {
		return nil, fmt.Errorf("failed to parse external IP from UPnP response: %s", string(body))
	}

	ip := net.ParseIP(strings.TrimSpace(ipResp.IP))
	if ip == nil {
		return nil, fmt.Errorf("invalid external IP in UPnP response: %s", ipResp.IP)
	}

	return ip, nil
}

// DeletePortMapping removes an existing UDP port mapping from the gateway router.
func (m *UPnPMapper) DeletePortMapping(ctx context.Context, externalPort int) error {
	soapBody := fmt.Sprintf(
		`<?xml version="1.0"?>`+
			`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`+
			`<s:Body>`+
			`<u:DeletePortMapping xmlns:u="%s">`+
			`<NewRemoteHost></NewRemoteHost>`+
			`<NewExternalPort>%d</NewExternalPort>`+
			`<NewProtocol>UDP</NewProtocol>`+
			`</u:DeletePortMapping>`+
			`</s:Body>`+
			`</s:Envelope>`,
		m.serviceType, externalPort,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", m.controlURL, bytes.NewBufferString(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#DeletePortMapping"`, m.serviceType))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// TryUPnPMapping attempts to automatically map the UDP port on a local UPnP IGD router.
// Returns the mapped public address (*net.UDPAddr) and a cleanup function if successful,
// or (nil, nil) if UPnP is unavailable/unsupported.
func TryUPnPMapping(ctx context.Context, port int, description string) (*net.UDPAddr, func()) {
	discoveryCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	mapper, err := DiscoverUPnPGateway(discoveryCtx, 1500*time.Millisecond)
	if err != nil || mapper == nil {
		return nil, nil
	}

	lanIPs, _ := GatherHostCandidates(port)
	if len(lanIPs) == 0 {
		return nil, nil
	}
	// Extract IP only
	internalHost, _, err := net.SplitHostPort(lanIPs[0])
	if err != nil {
		internalHost = lanIPs[0]
	}

	if err := mapper.AddPortMapping(ctx, port, port, internalHost, description); err != nil {
		return nil, nil
	}

	extIP, err := mapper.GetExternalIPAddress(ctx)
	if err != nil || extIP == nil {
		return nil, func() {
			_ = mapper.DeletePortMapping(context.Background(), port)
		}
	}

	mappedAddr := &net.UDPAddr{
		IP:   extIP,
		Port: port,
	}

	cleanup := func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer delCancel()
		_ = mapper.DeletePortMapping(delCtx, port)
	}

	return mappedAddr, cleanup
}
