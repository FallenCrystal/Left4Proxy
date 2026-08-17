package discover

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	ssdpMulticastAddr = "239.255.255.250:1900"
	ssdpDiscoverMsg   = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n\r\n"
	maxUPnPDescriptionBytes = 1 << 20
	maxUPnPErrorBytes       = 16 << 10
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
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return nil, errors.New("UPnP discovery timeout must be positive")
	}
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

	client := newUPnPHTTPClient(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		location := extractLocation(string(buf[:n]))
		if location == "" || len(location) > 2048 {
			continue
		}
		parsedLocation, parseErr := url.Parse(location)
		if parseErr != nil || !isLocalUPnPHost(parsedLocation, source) {
			continue
		}

		mapper, err := parseRootDesc(ctx, client, location)
		if err == nil && mapper != nil {
			return mapper, nil
		}
	}

	return nil, fmt.Errorf("no UPnP IGD gateway discovered")
}

func newUPnPHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}
			previous := via[len(via)-1].URL
			if req.URL.Scheme != previous.Scheme || !strings.EqualFold(req.URL.Host, previous.Host) {
				return errors.New("UPnP redirect changes scheme or host")
			}
			return nil
		},
	}
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
	if client == nil {
		return nil, errors.New("UPnP HTTP client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	parsedLoc, err := url.Parse(strings.TrimSpace(locURL))
	if err != nil {
		return nil, fmt.Errorf("invalid UPnP description URL: %w", err)
	}
	if err := validateUPnPURL(parsedLoc); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", locURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL != nil && (resp.Request.URL.Scheme != parsedLoc.Scheme || !strings.EqualFold(resp.Request.URL.Host, parsedLoc.Host)) {
		return nil, errors.New("UPnP description redirect changes scheme or host")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("UPnP description HTTP %d", resp.StatusCode)
	}

	body, err := readLimited(resp.Body, maxUPnPDescriptionBytes)
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
	if err := validateServiceType(srv.ServiceType); err != nil {
		return nil, err
	}

	ctrlURL, err := parsedLoc.Parse(srv.ControlURL)
	if err != nil {
		return nil, err
	}
	if err := validateUPnPURL(ctrlURL); err != nil {
		return nil, fmt.Errorf("invalid UPnP control URL: %w", err)
	}

	return &UPnPMapper{
		controlURL:  ctrlURL.String(),
		serviceType: srv.ServiceType,
		httpClient:  client,
	}, nil
}

func validateUPnPURL(value *url.URL) error {
	if value == nil || (value.Scheme != "http" && value.Scheme != "https") || value.Hostname() == "" {
		return errors.New("UPnP URL must use http(s) and include a host")
	}
	if value.User != nil {
		return errors.New("UPnP URL userinfo is not allowed")
	}
	if ip := net.ParseIP(value.Hostname()); ip != nil {
		if !isLocalNetworkIP(ip) {
			return errors.New("UPnP URL host must be on the local network")
		}
		return nil
	}
	// A device may publish a local DNS name instead of a literal gateway IP.
	// Resolve it before allowing the request; accepting an arbitrary hostname
	// here would turn a malicious device description into an SSRF primitive.
	resolved, err := net.LookupIP(value.Hostname())
	if err != nil || len(resolved) == 0 {
		return errors.New("UPnP URL hostname does not resolve to a local address")
	}
	for _, ip := range resolved {
		if isLocalNetworkIP(ip) {
			return nil
		}
	}
	return errors.New("UPnP URL host must resolve to the local network")
}

func isLocalUPnPHost(value *url.URL, source *net.UDPAddr) bool {
	if err := validateUPnPURL(value); err != nil {
		return false
	}
	hostIP := net.ParseIP(value.Hostname())
	if hostIP == nil {
		// SSDP implementations normally publish a literal gateway address. Keep
		// hostname locations compatible when they resolve to a local address.
		resolved, err := net.LookupIP(value.Hostname())
		if err != nil {
			return false
		}
		for _, ip := range resolved {
			if isLocalNetworkIP(ip) && (source == nil || source.IP == nil || ip.Equal(source.IP) || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
				return true
			}
		}
		return false
	}
	if source != nil && source.IP != nil && hostIP.Equal(source.IP) {
		return true
	}
	return isLocalNetworkIP(hostIP)
}

func isLocalNetworkIP(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid response size limit")
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("UPnP response exceeds %d bytes", limit)
	}
	return body, nil
}

func xmlEscape(value string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

func validateServiceType(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\"\r\n\t") {
		return errors.New("UPnP service type is empty or contains unsafe header characters")
	}
	return nil
}

func soapAction(serviceType, action string) (string, error) {
	if err := validateServiceType(serviceType); err != nil {
		return "", err
	}
	return fmt.Sprintf(`"%s#%s"`, serviceType, action), nil
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
	if m == nil || m.httpClient == nil {
		return errors.New("UPnP mapper is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateMappingPort(externalPort); err != nil {
		return fmt.Errorf("external port: %w", err)
	}
	if err := validateMappingPort(internalPort); err != nil {
		return fmt.Errorf("internal port: %w", err)
	}
	internalIP = strings.TrimSpace(internalIP)
	if net.ParseIP(internalIP) == nil {
		return fmt.Errorf("internal client %q is not an IP address", internalIP)
	}
	if strings.ContainsAny(description, "\r\n") {
		return errors.New("UPnP mapping description contains a newline")
	}
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
		xmlEscape(m.serviceType), externalPort, internalPort, xmlEscape(internalIP), xmlEscape(description),
	)

	req, err := http.NewRequestWithContext(ctx, "POST", m.controlURL, bytes.NewBufferString(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	action, err := soapAction(m.serviceType, "AddPortMapping")
	if err != nil {
		return err
	}
	req.Header.Set("SOAPAction", action)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := readLimited(resp.Body, maxUPnPErrorBytes)
		return fmt.Errorf("UPnP AddPortMapping HTTP %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

// GetExternalIPAddress queries the router's external public IP address.
func (m *UPnPMapper) GetExternalIPAddress(ctx context.Context) (net.IP, error) {
	if m == nil || m.httpClient == nil {
		return nil, errors.New("UPnP mapper is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	soapBody := fmt.Sprintf(
		`<?xml version="1.0"?>`+
			`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`+
			`<s:Body>`+
			`<u:GetExternalIPAddress xmlns:u="%s">`+
			`</u:GetExternalIPAddress>`+
			`</s:Body>`+
			`</s:Envelope>`,
		xmlEscape(m.serviceType),
	)

	req, err := http.NewRequestWithContext(ctx, "POST", m.controlURL, bytes.NewBufferString(soapBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	action, err := soapAction(m.serviceType, "GetExternalIPAddress")
	if err != nil {
		return nil, err
	}
	req.Header.Set("SOAPAction", action)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := readLimited(resp.Body, maxUPnPErrorBytes)
		return nil, fmt.Errorf("UPnP GetExternalIPAddress HTTP %d: %s", resp.StatusCode, string(body))
	}
	body, err := readLimited(resp.Body, maxUPnPErrorBytes)
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
	if m == nil || m.httpClient == nil {
		return errors.New("UPnP mapper is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateMappingPort(externalPort); err != nil {
		return fmt.Errorf("external port: %w", err)
	}
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
		xmlEscape(m.serviceType), externalPort,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", m.controlURL, bytes.NewBufferString(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	action, err := soapAction(m.serviceType, "DeletePortMapping")
	if err != nil {
		return err
	}
	req.Header.Set("SOAPAction", action)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := readLimited(resp.Body, maxUPnPErrorBytes)
		return fmt.Errorf("UPnP DeletePortMapping HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func validateMappingPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is outside 1..65535", port)
	}
	return nil
}

// TryUPnPMapping attempts to automatically map the UDP port on a local UPnP IGD router.
// Returns the mapped public address (*net.UDPAddr) and a cleanup function if successful,
// or (nil, nil) if UPnP is unavailable/unsupported.
func TryUPnPMapping(ctx context.Context, port int, description string) (*net.UDPAddr, func()) {
	if err := validateMappingPort(port); err != nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
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
	// WANIPConnection mappings target an IPv4 LAN client. IPv6 candidates are
	// useful for endpoint advertisement but are not valid NewInternalClient
	// values for the IGD service used here.
	internalHost, _, err := net.SplitHostPort(lanIPs[0])
	if err != nil || net.ParseIP(internalHost) == nil || net.ParseIP(internalHost).To4() == nil {
		return nil, nil
	}

	if err := mapper.AddPortMapping(ctx, port, port, internalHost, description); err != nil {
		return nil, nil
	}

	extIP, err := mapper.GetExternalIPAddress(ctx)
	if err != nil || !isUsableExternalIP(extIP) {
		// AddPortMapping succeeded, so a later discovery/parse failure must
		// immediately undo it. Returning a cleanup callback alongside a nil
		// address is too easy for callers to discard and leaves a permanent
		// router mapping behind.
		cleanupUPnPMapping(mapper, port)
		return nil, nil
	}

	mappedAddr := &net.UDPAddr{
		IP:   extIP,
		Port: port,
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() { cleanupUPnPMapping(mapper, port) })
	}

	return mappedAddr, cleanup
}

func cleanupUPnPMapping(mapper *UPnPMapper, port int) {
	if mapper == nil {
		return
	}
	delCtx, delCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer delCancel()
	if err := mapper.DeletePortMapping(delCtx, port); err != nil {
		// Cleanup is best effort, but make a failed deletion visible to operators;
		// otherwise they may assume the router no longer exposes the port.
		log.Printf("[UPnP] failed to remove UDP mapping on port %d: %v", port, err)
	}
}

func isUsableExternalIP(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	if isCarrierGradeNAT(ip) {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

func isCarrierGradeNAT(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
	}
	return false
}
