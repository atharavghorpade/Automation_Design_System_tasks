var metadata = {
    groupIdNumber: "1.52",
    stigId: "CISC-RT-000500",
    ruleId: "RULE ID: SV-216598r531085",
    groupId: "GROUP ID: V-216598",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to reject inbound route advertisements for  any prefixes belonging to the local autonomous system (AS).  GROUP ID: V-216598  RULE ID: SV-216598r531085",
    rationale: "Accepting route advertisements belonging to the local AS can result in traffic looping or  being black holed, or at a minimum using a non-optimized path.",
    audit: "Review the router configuration to verify that it will reject routes belonging to the local  AS.  Step 1: Verify a prefix list has been configured containing prefixes belonging to the local  AS. In the example below x.13.1.0/24 is the global address space allocated to the local  AS.  ip prefix-list PREFIX_FILTER seq 5 deny 0.0.0.0/8 le 32  …  …  …  ip prefix-list PREFIX_FILTER seq 74 deny x.13.1.0/24 le 32  ip prefix-list PREFIX_FILTER seq 75 permit 0.0.0.0/0 ge 8  Step 2: Verify that the prefix list has been applied to all external BGP peers as shown in  the example below.  router bgp xx  no synchronization  bgp log-neighbor-changes  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 prefix-list PREFIX_FILTER in  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 prefix-list PREFIX_FILTER in  If the router is not configured to reject inbound route advertisements belonging to the  local AS, this is a finding.  Internal Only - General",
    remediation: "Configure the router to reject inbound route advertisements for any prefixes belonging  to the local AS.  Step 1: Add to the prefix filter list those prefixes belonging to the local autonomous  system.  R1(config)#ip prefix-list PREFIX_FILTER seq 74 deny x.13.1.0/24 le 32  Step 2: If not already completed to be compliant with previous requirement, apply the  prefix list filter inbound to each external BGP neighbor as shown in the example.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 prefix-list PREFIX_FILTER in  R1(config-router)#neighbor x.2.1.7 prefix-list PREFIX_FILTER in",
    cci: "CCI-001368",
    expectedState: "Configure the router to reject inbound route advertisements for any prefixes belonging to the local AS.",
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
