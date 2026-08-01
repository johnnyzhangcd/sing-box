package globalprotect

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"math"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	maximumHIPReportSize    = 8 << 20
	defaultHIPCheckInterval = time.Hour
	minimumHIPCheckInterval = time.Second
)

func parseHIPCheckInterval(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultHIPCheckInterval, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return 0, E.Cause(err, "parse GlobalProtect HIP report interval")
	}
	if seconds == 0 {
		return defaultHIPCheckInterval, nil
	}
	if seconds > math.MaxInt64/uint64(time.Second) {
		return 0, E.New("GlobalProtect HIP report interval is too large: ", seconds)
	}
	interval := time.Duration(seconds) * time.Second
	if interval > time.Minute {
		return interval - time.Minute, nil
	}
	interval /= 2
	if interval < minimumHIPCheckInterval {
		interval = minimumHIPCheckInterval
	}
	return interval, nil
}

type hipReportXML struct {
	XMLName          xml.Name         `xml:"hip-report"`
	Name             string           `xml:"name,attr"`
	MD5Sum           string           `xml:"md5-sum"`
	UserName         string           `xml:"user-name"`
	Domain           string           `xml:"domain"`
	HostName         string           `xml:"host-name"`
	IPAddress        string           `xml:"ip-address,omitempty"`
	IPv6Address      string           `xml:"ipv6-address,omitempty"`
	GenerateTime     string           `xml:"generate-time"`
	HIPReportVersion int              `xml:"hip-report-version"`
	Categories       hipCategoriesXML `xml:"categories"`
}

type hipCategoriesXML struct {
	Entries []hipCategoryXML `xml:"entry"`
}

type hipCategoryXML struct {
	Name                  string                   `xml:"name,attr"`
	ClientVersion         *string                  `xml:"client-version,omitempty"`
	OperatingSystem       string                   `xml:"os,omitempty"`
	OperatingSystemVendor string                   `xml:"os-vendor,omitempty"`
	Domain                *string                  `xml:"domain,omitempty"`
	HostName              string                   `xml:"host-name,omitempty"`
	NetworkInterfaces     *hipNetworkInterfacesXML `xml:"network-interface,omitempty"`
	List                  *hipEmptyXML             `xml:"list,omitempty"`
	MissingPatches        *hipEmptyXML             `xml:"missing-patches,omitempty"`
}

type hipNetworkInterfacesXML struct {
	Entries []hipNetworkInterfaceXML `xml:"entry"`
}

type hipNetworkInterfaceXML struct {
	Name       string `xml:"name,attr"`
	MACAddress string `xml:"mac-address"`
}

type hipEmptyXML struct{}

func buildHIPReport(cookie string, prefixes []netip.Prefix, localHostname string, reportedOS string, appVersion string) ([]byte, error) {
	filteredCookie := filterCookieOptions(cookie, "authcookie", "preferred-ip", "preferred-ipv6")
	// GlobalProtect uses MD5 here as a correlation identifier, not a security primitive.
	digest := md5.Sum([]byte(filteredCookie)) //nolint:gosec
	md5Text := hex.EncodeToString(digest[:])

	cookieValues, err := url.ParseQuery(cookie)
	if err != nil {
		return nil, E.Cause(err, "parse GlobalProtect HIP cookie")
	}
	var ipv4Address string
	var ipv6Address string
	for _, prefix := range prefixes {
		address := prefix.Addr().Unmap()
		switch {
		case address.Is4() && ipv4Address == "":
			ipv4Address = address.String()
		case address.Is6() && ipv6Address == "":
			ipv6Address = address.String()
		}
	}
	if ipv4Address == "" && ipv6Address == "" {
		return nil, E.New("GlobalProtect HIP report requires an assigned IP address")
	}
	if appVersion == "" {
		appVersion = defaultAppVersion
	}
	operatingSystem, operatingSystemVendor := hipOperatingSystem(reportedOS)
	interfaces, err := hipNetworkInterfaces()
	if err != nil {
		return nil, err
	}
	domain := cookieValues.Get("domain")
	emptyList := &hipEmptyXML{}
	categories := []hipCategoryXML{{
		Name:                  "host-info",
		ClientVersion:         &appVersion,
		OperatingSystem:       operatingSystem,
		OperatingSystemVendor: operatingSystemVendor,
		Domain:                &domain,
		HostName:              localHostname,
		NetworkInterfaces:     &hipNetworkInterfacesXML{Entries: interfaces},
	}}
	for _, categoryName := range []string{
		"antivirus",
		"anti-malware",
		"anti-spyware",
		"disk-backup",
		"disk-encryption",
		"firewall",
	} {
		categories = append(categories, hipCategoryXML{Name: categoryName, List: emptyList})
	}
	categories = append(categories,
		hipCategoryXML{Name: "patch-management", List: emptyList, MissingPatches: emptyList},
		hipCategoryXML{Name: "data-loss-prevention", List: emptyList},
	)
	reportDocument := hipReportXML{
		Name:             "hip-report",
		MD5Sum:           md5Text,
		UserName:         cookieValues.Get("user"),
		Domain:           domain,
		HostName:         localHostname,
		IPAddress:        ipv4Address,
		IPv6Address:      ipv6Address,
		GenerateTime:     time.Now().Format("01/02/2006 15:04:05"),
		HIPReportVersion: 4,
		Categories:       hipCategoriesXML{Entries: categories},
	}
	reportContent, err := xml.MarshalIndent(reportDocument, "", "\t")
	if err != nil {
		return nil, E.Cause(err, "encode GlobalProtect HIP report")
	}
	report := make([]byte, 0, len(xml.Header)+len(reportContent)+1)
	report = append(report, xml.Header...)
	report = append(report, reportContent...)
	report = append(report, '\n')
	if len(report) > maximumHIPReportSize {
		return nil, E.New("GlobalProtect HIP report exceeds ", maximumHIPReportSize, " bytes")
	}
	return report, nil
}

func buildHIPSubmitBody(cookie string, prefixes []netip.Prefix, report []byte) string {
	var q queryBuilder
	q.Add("client-role", "global-protect-full")
	q.AddRaw(cookie)
	for _, prefix := range prefixes {
		address := prefix.Addr().Unmap()
		switch {
		case address.Is4():
			q.Add("client-ip", address.String())
		case address.Is6():
			q.Add("client-ipv6", address.String())
		}
	}
	q.Add("report", string(report))
	return q.String()
}

func parseHIPSubmitXML(content []byte) error {
	type hipSubmitXML struct {
		Status string `xml:"status,attr"`
		Error  string `xml:"error"`
	}
	var response hipSubmitXML
	if err := xml.Unmarshal(content, &response); err != nil {
		return E.Cause(err, "parse GlobalProtect HIP report response")
	}
	status := strings.TrimSpace(response.Status)
	serverError := strings.TrimSpace(response.Error)
	if (status != "" && !strings.EqualFold(status, "success")) || serverError != "" {
		if serverError == "" {
			serverError = status
		}
		return E.New("GlobalProtect HIP report rejected: ", serverError)
	}
	return nil
}

func hipOperatingSystem(reportedOS string) (string, string) {
	switch gpstClientOS(reportedOS) {
	case "Mac":
		return "Apple macOS " + runtime.GOARCH, "Apple"
	case "Windows":
		return "Microsoft Windows " + runtime.GOARCH, "Microsoft"
	case "Android":
		return "Android " + runtime.GOARCH, "Google"
	case "iOS":
		return "Apple iOS " + runtime.GOARCH, "Apple"
	default:
		return "Linux " + runtime.GOARCH, "Linux"
	}
}

func hipNetworkInterfaces() ([]hipNetworkInterfaceXML, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, E.Cause(err, "list network interfaces for GlobalProtect HIP report")
	}
	sort.Slice(interfaces, func(i int, j int) bool {
		if interfaces[i].Name == interfaces[j].Name {
			return interfaces[i].Index < interfaces[j].Index
		}
		return interfaces[i].Name < interfaces[j].Name
	})
	reports := make([]hipNetworkInterfaceXML, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		macAddress := formatHIPMAC(networkInterface.HardwareAddr)
		if macAddress == "" {
			continue
		}
		reports = append(reports, hipNetworkInterfaceXML{
			Name:       networkInterface.Name,
			MACAddress: macAddress,
		})
	}
	return reports, nil
}

func formatHIPMAC(address net.HardwareAddr) string {
	if len(address) == 0 {
		return ""
	}
	allZero := true
	for _, value := range address {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return strings.ToUpper(strings.ReplaceAll(address.String(), ":", "-"))
}
