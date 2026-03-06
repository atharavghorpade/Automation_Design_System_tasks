var metadata = {
    groupIdNumber: "1.1",
    stigId: "CISC-RT-000010",
    ruleId: "RULE ID: SV-216551r531085",
    groupId: "GROUP ID: V-216551",
    severity: "HIGH",
    description: "The Cisco router must be configured to enforce approved authorizations for controlling  the flow of information within the network based on organization-defined information  flow control policies.  GROUP ID: V-216551  RULE ID: SV-216551r531085",
    rationale: "Information flow control regulates where information is allowed to travel within a network  and between interconnected networks. The flow of all network traffic must be monitored  and controlled so it does not introduce any unacceptable risk to the network  infrastructure or data. Information flow control policies and enforcement mechanisms  are commonly employed by organizations to control the flow of information between  designated sources and destinations (e.g., networks, individuals, and devices) within  information systems.  Enforcement occurs, for example, in boundary protection devices (e.g., gateways,  routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish  configuration settings that restrict information system services, provide a packet filtering  capability based on header information, or provide a message filtering capability based  on message content (e.g., implementing key word searches or using document  characteristics).  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify that Access Control Lists (ACLs) are configured  to allow or deny traffic for specific source and destination addresses as well as ports  and protocols. For example, the configuration below will allow only printer traffic into  subnet 10.1.23.0/24 and SQL traffic into subnet 10.1.24.0/24. ICMP is allowed for  troubleshooting and OSPF is the routing protocol used within the network.  interface GigabitEthernet1/1  description link to core  ip address 10.1.12.2 255.255.255.0  ip access-group FILTER_SERVER_TRAFFIC in  …  …  …  ip access-list extended FILTER_SERVER_TRAFFIC  permit tcp any 10.1.23.0 0.0.0.255 eq lpd 631 9100  permit tcp any 10.1.24.0 0.0.0.255 eq 1433 1434 4022  permit icmp any any  permit ospf any any  deny ip any any  If the router is not configured to enforce approved authorizations for controlling the flow  of information within the network based on organization-defined information flow control  policies, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure ACLs to allow or deny traffic for specific source and destination addresses as  well as ports and protocols between various subnets as required. The commands used  below were used to create the configuration as shown in the check content.  R5(config)#ip access-list extended FILTER_SERVER_TRAFFIC  R5(config-ext-nacl)#permit tcp any 10.1.23.0 0.0.0.255 eq 515 631 9100  R5(config-ext-nacl)#permit tcp any 10.1.24.0 0.0.0.255 eq 1433 1434 4022  R5(config-ext-nacl)#permit icmp any any  R5(config-ext-nacl)#permit ospf any any  R5(config-ext-nacl)#deny ip any any  R5(config-ext-nacl)#exit  R5(config)#interface GigabitEthernet1/1  R5(config-if)#ip access-group FILTER_SERVER_TRAFFIC in     Internal Only - General",
    cci: "CCI-001368",
    expectedState: "Configure ACLs to allow or deny traffic for specific source and destination addresses as well as ports and protocols between various subnets as required.",
    generatedOn: "2026-03-06",
    generatorVersion: "2.0",
    benchmark: "STIG"
};

function check(config) {

    if (!config) {
        return { status: "ERROR", line: 0 };
    }

    var lines = String(config).split("\n");
    var matched = false;
    var foundLine = 0;
    var pass = true;

    for (var i = 0; i < lines.length; i++) {

        var line = lines[i].toLowerCase();

        if (line.indexOf("###NO_MATCH###".toLowerCase()) !== -1) {

            matched = true;
            foundLine = i + 1;

            var numberMatch = line.match(/\d+/);
            var actual = numberMatch ? parseInt(numberMatch[0]) : null;

            pass = true;
        }
    }

    if ("exists" === "not_exists") {
        if (matched) {
            return { status: "FAIL", line: foundLine };
        } else {
            return { status: "PASS", line: 0 };
        }
    }

    if (!matched) {
        return { status: "FAIL", line: 0 };
    }

    if (pass) {
        return { status: "PASS", line: foundLine };
    }

    return { status: "FAIL", line: foundLine };
}

check(config);
