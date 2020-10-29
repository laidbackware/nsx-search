package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
)

var out io.Writer = os.Stdout
var hostName string
var userName *string
var password *string

func getAPIResouces() map[string][]string {
	var apiResources = map[string][]string{
		"manager": {"AdvertisementConfig", "AdvertiseRuleList", "BGPCommunityList", "BgpConfig", "BgpNeighbor",
			"BridgeEndpointProfile", "BridgeHighAvailabilityClusterProfile", "certificate_ca", "certificate_self_signed",
			"certificate_signed", "ClusterNodeConfig", "ComputeCollection", "ComputeManager", "crl", "DhcpIpPool",
			"DhcpProfile", "DhcpRelayProfile", "DhcpRelayService", "DirectoryAdDomain", "DirectoryGroup", "DirectoryLdapServer",
			"DiscoveredNode", "DnsForwarder", "EdgeCluster", "EdgeHighAvailabilityProfile", "EdgeNode", "ExcludeList",
			"ExtraConfigHostSwitchProfile", "FirewallRule", "FirewallSection", "GiConfigDashboardInfo", "GiServiceProfile",
			"HostHealthAggregateStatus", "HostNode", "IDSSignatureDetail", "IpBlock", "IpDiscoverySwitchingProfile",
			"IpfixCollectorConfig", "IpfixDfwConfig", "IpfixObsPointConfig", "IpPool", "IPPrefixList", "IPSecVPNLocalEndpoint",
			"IPSecVPNPeerEndpoint", "IPSecVPNService", "IPSecVPNTunnelProfile", "IPSet", "L2VpnService", "L2VpnSession",
			"LbClientSslProfile", "LbCookiePersistenceProfile", "LbFastTcpProfile", "LbFastUdpProfile",
			"LbGenericPersistenceProfile", "LbHttpMonitor", "LbHttpProfile", "LbHttpsMonitor", "LbIcmpMonitor",
			"LbPassiveMonitor", "LbPool", "LbServerSslProfile", "LbService", "LbSourceIpPersistenceProfile", "LbTcpMonitor",
			"LbUdpMonitor", "LbVirtualServer", "LldpHostSwitchProfile", "LogicalDhcpServer", "LogicalPort", "LogicalRouter",
			"LogicalRouterCentralizedServicePort", "LogicalRouterDownLinkPort", "LogicalRouterIPTunnelPort",
			"LogicalRouterLinkPortOnTIER0", "LogicalRouterLinkPortOnTIER1", "LogicalRouterUpLinkPort", "LogicalSwitch",
			"MacManagementSwitchingProfile", "MACSet", "MetadataProxy", "NatRule", "NiocProfile", "NSGroup", "NSProfile",
			"NSService", "NSServiceGroup", "PolicyBasedIPSecVPNSession", "PortMirroringSwitchingProfile", "PrincipalIdentity",
			"QosSwitchingProfile", "RedistributionConfig", "RedistributionRuleList", "RouteBasedIPSecVPNSession", "RouteMap",
			"RoutingConfig", "ServiceDefinition", "ServiceInsertionRule", "ServiceInsertionSection", "ServiceInsertionServiceProfile",
			"ServiceProfileNSGroups", "SIExcludeList", "SpoofGuardSwitchingProfile", "StaticHopBfdPeer", "StaticRoute",
			"SwitchSecuritySwitchingProfile", "TransportNode", "TransportZone", "UplinkHostSwitchProfile", "VendorTemplate",
			"VirtualMachine", "VirtualNetworkInterface", "VmHealthAggregateStatus", "VniPool"},

		"policy": {"ALGTypeServiceEntry", "ALGTypeServiceEntry", "BfdConfiguration", "BgpNeighborConfig", "BgpRoutingConfig",
			"BridgeEndpointProfile", "certificate_ca", "certificate_self_signed", "certificate_signed", "ClusterNodeConfig",
			"CommunityList", "ComputeManager", "crl", "DfwFirewallConfiguration", "DhcpServerConfig", "DnsSecurityProfile",
			"DOMAIN", "EdgeCluster", "EdgeHighAvailabilityProfile", "EdgeNode", "EndpointPolicy", "EndpointRule", "EnforcementPoint",
			"EtherTypeServiceEntry", "FloodProtectionProfileBindingMap", "ForwardingPolicy", "ForwardingRule",
			"GatewayFloodProtectionProfile", "GatewayPolicy", "GatewayQosProfile", "GenericPolicyRealizedResource", "GlobalConfig",
			"Group", "HostNode", "ICMPTypeServiceEntry", "IdsConfig", "IdsProfile", "IdsRule", "IdsSecurityPolicy", "IdsSettings",
			"IdsSignature", "IdsSignatureVersion", "IGMPTypeServiceEntry", "IpAddressBlock", "IpAddressPool", "IpAddressPoolBlockSubnet",
			"IpAddressPoolStaticSubnet", "IPDiscoveryProfile", "IPFIXDFWCollectorProfile", "IPFIXDFWProfile", "IPProtocolServiceEntry",
			"IPSecVpnDpdProfile", "IPSecVpnIkeProfile", "IPSecVpnLocalEndpoint", "IPSecVpnRule", "IPSecVpnService",
			"IPSecVpnTunnelInterface", "IPSecVpnTunnelProfile", "Ipv6DadProfile", "Ipv6NdraProfile", "L2BridgeEndpointProfile",
			"L2VPNService", "L2VPNSession", "L4PortSetServiceEntry", "LBClientSslProfile", "LBCookiePersistenceProfile",
			"LBFastTcpProfile", "LBFastUdpProfile", "LBGenericPersistenceProfile", "LBHttpMonitorProfile", "LBHttpProfile",
			"LBHttpsMonitorProfile", "LBIcmpMonitorProfile", "LBPassiveMonitorProfile", "LBPool", "LBServerSslProfile", "LBService",
			"LBSourceIpPersistenceProfile", "LBTcpMonitorProfile", "LBUdpMonitorProfile", "LBVirtualServer", "LocaleServices",
			"MacDiscoveryProfile", "MetadataProxyConfig", "PolicyBasedIPSecVpnSession", "PolicyContextProfile", "PolicyDnsForwarder",
			"PolicyDnsForwarderZone", "PolicyDraft", "PolicyEdgeCluster", "PolicyEdgeNode", "PolicyExcludeList",
			"PolicyFirewallSessionTimerProfile", "PolicyIgmpConfig", "PolicyMulticastConfig", "PolicyNat", "PolicyNatRule",
			"PolicyPimConfig", "PolicyServiceChain", "PolicyServiceProfile", "PolicyTransportZone", "PrefixList",
			"RealizedVirtualMachine", "RedirectionPolicy", "RedirectionRule", "RouteBasedIPSecVpnSession", "Rule", "SecurityPolicy",
			"Segment", "SegmentPort", "SegmentSecurityProfile", "Service", "ServiceReference", "ServiceSegment",
			"SessionTimerProfileBindingMap", "Site", "SpoofGuardProfile", "StandaloneHostIdfwConfiguration", "StaticRouteBfdPeer",
			"StaticRoutes", "Tier0", "Tier0Interface", "Tier0RouteMap", "Tier1", "Tier1Interface", "TlsCertificate", "TlsCrl",
			"TraceflowConfig", "TransportNode", "TransportZone", "UplinkHostSwitchProfile", "VniPoolConfig",
		},
	}
	return apiResources
}

func generateURL(objectType string, objectName string, endpointBase string) string {
	baseURL := "https://" + hostName + endpointBase
	fullURL := baseURL + "/search/query?query=resource_type:" + objectType
	if objectName != "" {
		fullURL = fullURL + url.QueryEscape(" AND display_name:"+objectName)
	}
	return fullURL
}

func search(fullURL string) (string, error) {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth(*userName, *password)
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		fmt.Fprintln(out, bodyString)
		return bodyString, nil
	} else if resp.StatusCode == http.StatusForbidden {
		fmt.Fprintln(out, "Access forbidden. Please check the username or password")
	} else {
		fmt.Fprintln(out, resp.StatusCode)
	}
	return "", err
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func main() {

	// var hostName string
	// var userName string
	// var password string
	// var insecureMode bool
	// var objectType string

	commandLine := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// commandLine.StringVar(&optionMode, "mode", "add",
	// 	"Choose 'add' or 'multiply'")
	// commandLine.PrintDefaults()
	// commandLine.Parse(os.Args[1:])
	// flag.StringVar(&hostName, "hostname", "", "NSX-T Manager Hostname")
	// flag.StringVar(&userName, "username", "", "NSX-T Manager username")
	// flag.StringVar(&password, "password", "", "NSX-T Manager password")
	// flag.BoolVar(&insecureMode, "insecure", true, "Skip TLS verification. Default true.")
	// flag.StringVar(&objectType, "object-type", "", "API object to query")

	hostName = *commandLine.StringP("endpoint", "e", "", "NSX-T Manager Hostname")
	userName = commandLine.StringP("username", "u", "", "NSX-T Manager username")
	password = commandLine.StringP("password", "p", "", "NSX-T Manager password")
	managerAPI := commandLine.BoolP("manager-api", "m", false, "User manager API. Defaults to false, which uses the policy API")
	insecureMode := commandLine.BoolP("insecure", "k", false, "Skip TLS verification. Default true.")
	objectType := commandLine.StringP("object-type", "o", "", "Type of object to query")
	objectName := commandLine.StringP("object-name", "n", "", "Optional. Name of object to query. Without a name, all objects will be returned, up to 1000.")

	commandLine.Parse(os.Args[1:])

	apiType := "policy"
	endpointBase := "/policy/api/v1"
	if *managerAPI {
		apiType = "manager"
		endpointBase = "/api/v1"
	}

	if hostName == "" || *userName == "" || *password == "" || *objectType == "" {
		fmt.Fprintln(out, "Incorrect usage")
		fmt.Fprintln(out, hostName)
		commandLine.PrintDefaults()
		os.Exit(1)
	}
	if *insecureMode {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	apiResources := getAPIResouces()
	_, found := Find(apiResources[apiType], *objectType)
	if !found {
		fmt.Fprintln(out, "Object type "+*objectType+" is not supported with the "+apiType+" API. Please use one of the following:")
		fmt.Fprintln(out, strings.Join(apiResources[apiType], ", "))
		os.Exit(1)
	}

	fullURL := generateURL(*objectType, *objectName, endpointBase)
	fmt.Fprintln(out, fullURL)
	_, _ = search(fullURL)

}
