var metadata = {
    groupIdNumber: "1.55",
    stigId: "CISC-RT-000530",
    ruleId: "RULE ID: SV-216601r531085",
    groupId: "GROUP ID: V-216601",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to reject outbound route advertisements for  any prefixes belonging to the IP core.  GROUP ID: V-216601  RULE ID: SV-216601r531085",
    rationale: "Outbound route advertisements belonging to the core can result in traffic either looping  or being black holed, or at a minimum, using a non-optimized path.",
    audit: "Step 1: Verify that a prefix list has been configured containing prefixes belonging to the  IP core.  ip prefix-list FILTER_CORE_PREFIXES seq 5 deny x.1.1.0/24 le 32  ip prefix-list FILTER _CORE_PREFIXES seq 10 deny x.1.2.0/24 le 32  ip prefix-list FILTER _CORE_PREFIXES seq 15 permit 0.0.0.0/0 ge 8  Step 2: Verify that the prefix lists has been applied to all external BGP peers as shown  in the example below.  router bgp xx  no synchronization  bgp log-neighbor-changes  neighbor x.1.4.12 remote-as yy  neighbor x.1.4.12 prefix-list FILTER _CORE_PREFIXES out  If the router is not configured to reject outbound route advertisements for prefixes  belonging to the IP core, this is a finding.",
    remediation: "Step 1: Configure a prefix list for containing all customer and local AS prefixes as shown  in the example below.  R1(config)#ip prefix-list FILTER_CORE_PREFIXES deny x.1.1.0/24 le 32  R1(config)#ip prefix-list FILTER _CORE_PREFIXES deny x.1.2.0/24 le 32  R1(config)#ip prefix-list FILTER _CORE_PREFIXES permit 0.0.0.0/0 ge 8  Step 2: Apply the prefix list filter outbound to each CE neighbor as shown in the  example.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.4.12 prefix-list FILTER _CORE_PREFIXES out  Internal Only - General",
    cci: "CCI-001097",
    expectedState: "Step 1: Configure a prefix list for containing all customer and local AS prefixes as shown in the example below.",
    generatedOn: "2026-03-02",
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
