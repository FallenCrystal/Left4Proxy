package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const mockRootXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/control/WANIPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>`

func TestUPnPMapperSOAPOperations(t *testing.T) {
	var receivedAddPort bool
	var receivedDeletePort bool
	var receivedGetIP bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("SOAPAction")
		switch {
		case r.URL.Path == "/rootDesc.xml":
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(mockRootXML))
		case action == `"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"`:
			receivedAddPort = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`))
		case action == `"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"`:
			receivedGetIP = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>198.51.100.25</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`))
		case action == `"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"`:
			receivedDeletePort = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mapper, err := parseRootDesc(ctx, server.Client(), fmt.Sprintf("%s/rootDesc.xml", server.URL))
	if err != nil {
		t.Fatalf("parseRootDesc failed: %v", err)
	}

	if err := mapper.AddPortMapping(ctx, 27014, 27014, "192.168.1.100", "Left4Proxy"); err != nil {
		t.Fatalf("AddPortMapping failed: %v", err)
	}
	if !receivedAddPort {
		t.Errorf("expected AddPortMapping request to be received")
	}

	ip, err := mapper.GetExternalIPAddress(ctx)
	if err != nil {
		t.Fatalf("GetExternalIPAddress failed: %v", err)
	}
	if !receivedGetIP || ip.String() != "198.51.100.25" {
		t.Errorf("expected IP 198.51.100.25, got %v", ip)
	}

	if err := mapper.DeletePortMapping(ctx, 27014); err != nil {
		t.Fatalf("DeletePortMapping failed: %v", err)
	}
	if !receivedDeletePort {
		t.Errorf("expected DeletePortMapping request to be received")
	}
}

func TestExtractLocation(t *testing.T) {
	header := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=120\r\n" +
		"LOCATION: http://192.168.1.1:49152/rootDesc.xml\r\n" +
		"SERVER: Linux/3.10 UPnP/1.0\r\n\r\n"

	loc := extractLocation(header)
	if loc != "http://192.168.1.1:49152/rootDesc.xml" {
		t.Errorf("extractLocation got %q, want http://192.168.1.1:49152/rootDesc.xml", loc)
	}
}

func TestUPnPRejectsHTTPFailuresAndBoundsBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("gateway failure"))
	}))
	defer server.Close()

	if _, err := parseRootDesc(context.Background(), server.Client(), server.URL+"/rootDesc.xml"); err == nil {
		t.Fatal("non-success root description status was accepted")
	}

	mapper := &UPnPMapper{
		controlURL:  server.URL,
		serviceType: "urn:schemas-upnp-org:service:WANIPConnection:1",
		httpClient:  server.Client(),
	}
	if err := mapper.DeletePortMapping(context.Background(), 27014); err == nil {
		t.Fatal("non-success DeletePortMapping status was accepted")
	}
	if err := mapper.AddPortMapping(context.Background(), 0, 27014, "192.168.1.2", "test"); err == nil {
		t.Fatal("invalid mapping port was accepted")
	}
}

func TestUPnPRejectsUnsafeDescriptionURL(t *testing.T) {
	client := &http.Client{}
	for _, location := range []string{"file:///tmp/root.xml", "http://user:pass@example.com/root.xml", "not a url"} {
		if _, err := parseRootDesc(context.Background(), client, location); err == nil {
			t.Fatalf("unsafe location %q was accepted", location)
		}
	}
}

func TestUPnPRejectsSOAPActionHeaderInjection(t *testing.T) {
	for _, serviceType := range []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1\"\r\nX-Injected: yes",
		"urn:schemas-upnp-org:service:WANIPConnection:1\tbad",
	} {
		if _, err := soapAction(serviceType, "GetExternalIPAddress"); err == nil {
			t.Fatalf("unsafe service type %q was accepted", serviceType)
		}
	}
}
