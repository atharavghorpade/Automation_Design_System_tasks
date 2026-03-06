var metadata = {
    groupIdNumber: "1.23",
    stigId: "CISC-RT-000290",
    ruleId: "RULE ID: SV-216577r531085",
    groupId: "GROUP ID: V-216577",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to not be a Border Gateway Protocol  (BGP) peer to an alternate gateway service provider.  GROUP ID: V-216577  RULE ID: SV-216577r531085",
    rationale: "ISPs use BGP to share route information with other autonomous systems (i.e. other  ISPs and corporate networks). If the perimeter router was configured to BGP peer with  an ISP, NIPRnet routes could be advertised to the ISP, thereby creating a backdoor  connection from the Internet to the NIPRnet.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration and verify that it is not BGP peering with an alternate  gateway service provider.  Step 1: Determine the ip address of the ISP router  interface GigabitEthernet0/2  description Link to ISP  ip address x.22.1.15 255.255.255.240  Step 2: Verify that the router is not BGP peering with this router.  router bgp nn  no synchronization  bgp log-neighbor-changes  neighbor x.11.1.7 remote-as nn  neighbor x.11.1.7 password xxxxxxx  no auto-summary  In the example above, the router is not peering with the ISP.  If the router is BGP peering with an alternate gateway service provider, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Remove any BGP neighbors belonging to the alternate gateway service provider and  configure a static route to forward Internet bound traffic to the alternate gateway as  shown in the example below.  R5(config)#ip route 0.0.0.0 0.0.0.0 x.22.1.14  Internal Only - General",
    cci: "CCI-001414",
    expectedState: "Remove any BGP neighbors belonging to the alternate gateway service provider and configure a static route to forward Internet bound traffic to the alternate gateway as shown in the example below.",
    generatedOn: "2026-03-06",
    generatorVersion: "2.1",
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

        if (line.indexOf("service provider".toLowerCase()) !== -1) {

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
