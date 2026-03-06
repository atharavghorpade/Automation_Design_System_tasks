var metadata = {
    groupIdNumber: "1.51",
    stigId: "CISC-RT-000490",
    ruleId: "RULE ID: SV-216597r877976",
    groupId: "GROUP ID: V-216597",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to reject inbound route advertisements for  any Bogon prefixes.  GROUP ID: V-216597  RULE ID: SV-216597r877976",
    rationale: "Accepting route advertisements for Bogon prefixes can result in the local autonomous  system (AS) becoming a transit for malicious traffic as it will in turn advertise these  prefixes to neighbor autonomous systems.  Internal Only - General",
    audit: "This check is Not Applicable for JRSS internal EBGP use.  Review the router configuration to verify that it will reject BGP routes for any Bogon  prefixes.  Step 1: Verify a prefix list has been configured containing the current Bogon prefixes as  shown in the example below.  ip prefix-list PREFIX_FILTER seq 5 deny 0.0.0.0/8 le 32  ip prefix-list PREFIX_FILTER seq 10 deny 10.0.0.0/8 le 32  ip prefix-list PREFIX_FILTER seq 15 deny 100.64.0.0/10 le 32  ip prefix-list PREFIX_FILTER seq 20 deny 127.0.0.0/8 le 32  ip prefix-list PREFIX_FILTER seq 25 deny 169.254.0.0/16 le 32  ip prefix-list PREFIX_FILTER seq 30 deny 172.16.0.0/12 le 32  ip prefix-list PREFIX_FILTER seq 35 deny 192.0.2.0/24 le 32  ip prefix-list PREFIX_FILTER seq 40 deny 192.88.99.0/24 le 32  ip prefix-list PREFIX_FILTER seq 45 deny 192.168.0.0/16 le 32  ip prefix-list PREFIX_FILTER seq 50 deny 198.18.0.0/15 le 32  ip prefix-list PREFIX_FILTER seq 55 deny 198.51.100.0/24 le 32  ip prefix-list PREFIX_FILTER seq 60 deny 203.0.113.0/24 le 32  ip prefix-list PREFIX_FILTER seq 65 deny 224.0.0.0/4 le 32  ip prefix-list PREFIX_FILTER seq 70 deny 240.0.0.0/4 le 32  ip prefix-list PREFIX_FILTER seq 75 permit 0.0.0.0/0 ge 8  Step 2: Verify that the prefix list has been applied to all external BGP peers as shown in  the example below.  router bgp xx  no synchronization  bgp log-neighbor-changes  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 prefix-list PREFIX_FILTER in  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 prefix-list PREFIX_FILTER in  Route Map Alternative  Verify that the route map applied to the external neighbors references the configured  Bogon prefix list shown above.  router bgp xx  no synchronization  bgp log-neighbor-changes  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 route-map FILTER_PREFIX_MAP  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 route-map FILTER_PREFIX_MAP  …  route-map FILTER_PREFIX_MAP permit 10  match ip address prefix-list PREFIX_FILTER  If the router is not configured to reject inbound route advertisements for any Bogon  prefixes, this is a finding.  Internal Only - General",
    remediation: "Configure the router to reject inbound route advertisements for any Bogon prefixes.  Step 1: Configure a prefix list containing the current Bogon prefixes as shown below.  R1(config)#ip prefix-list PREFIX_FILTER deny 0.0.0.0/8 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 10.0.0.0/8 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 100.64.0.0/10 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 127.0.0.0/8 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 169.254.0.0/16 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 172.16.0.0/12 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 192.0.2.0/24 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 192.88.99.0/24 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 192.168.0.0/16 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 198.18.0.0/15 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 198.51.100.0/24 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 203.0.113.0/24 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 224.0.0.0/4 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 240.0.0.0/4 le 32  R1(config)#ip prefix-list PREFIX_FILTER deny 240.0.0.0/4 le 32  R1(config)#ip prefix-list PREFIX_FILTER permit 0.0.0.0/0 ge 8  Step 2: Apply the prefix list filter inbound to each external BGP neighbor as shown in  the example.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 prefix-list PREFIX_FILTER in  R1(config-router)#neighbor x.2.1.7 prefix-list PREFIX_FILTER in  Route Map Alternative  Step 1: Configure the route map referencing the configured prefix list above.  R1(config)#route-map FILTER_PREFIX_MAP 10  R1(config-route-map)#match ip address prefix-list PREFIX_FILTER  R1(config-route-map)#exit  Step 2: Apply the route-map inbound to each external BGP neighbor as shown in the  example.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 route-map FILTER_PREFIX_MAP in  R1(config-router)#neighbor x.2.1.7 route-map FILTER_PREFIX_MAP in  R1(config-router)#end",
    cci: "CCI-001368",
    expectedState: "Configure the router to reject inbound route advertisements for any Bogon prefixes.",
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
