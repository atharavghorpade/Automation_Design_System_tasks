var metadata = {
    groupIdNumber: "1.49",
    stigId: "CISC-RT-000470",
    ruleId: "RULE ID: SV-216991r856208",
    groupId: "GROUP ID: V-216991",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to enable the Generalized TTL Security  Mechanism (GTSM).  GROUP ID: V-216991  RULE ID: SV-216991r856208",
    rationale: "As described in RFC 3682, GTSM is designed to protect a router's IP-based control  plane from DoS attacks. Many attacks focused on CPU load and line-card overload can  be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking  routers.  GTSM is based on the fact that the vast majority of control plane peering is established  between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either  between connecting interfaces or between loopback interfaces. Since TTL spoofing is  considered nearly impossible, a mechanism based on an expected TTL value provides  a simple and reasonably robust defense from infrastructure attacks based on forged  control plane traffic.",
    audit: "Review the BGP configuration to verify that TTL security has been configured for each  external neighbor as shown in the example below.  router bgp xx  no synchronization  bgp log-neighbor-changes  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 password xxxxxxxx  neighbor x.1.1.9 ttl-security hops 1  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 password xxxxxxxx  neighbor x.2.1.7 ttl-security hops 1  If the router is not configured to use GTSM for all Exterior Border Gateway Protocol  peering sessions, this is a finding.",
    remediation: "Configure TTL security on all external BGP neighbors as shown in the example below.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 ttl-security hops 1  R1(config-router)#neighbor x.2.1.7 ttl-security hops 1  Internal Only - General",
    cci: "CCI-002385",
    expectedState: "Configure TTL security on all external BGP neighbors as shown in the example below.",
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
