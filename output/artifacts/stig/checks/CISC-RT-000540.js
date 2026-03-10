var metadata = {
    groupIdNumber: "1.56",
    stigId: "CISC-RT-000540",
    ruleId: "SV-216602r531085",
    groupId: "V-216602",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to reject route advertisements from BGP  peers that do not list their autonomous system (AS) number as the first AS in the  AS_PATH attribute.  GROUP ID: V-216602  RULE ID: SV-216602r531085",
    rationale: "Verifying the path a route has traversed will ensure the IP core is not used as a transit  network for unauthorized or possibly even Internet traffic. All autonomous system  boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS  number as the first AS in the AS_PATH attribute.",
    audit: "Review the router configuration to verify the router is configured to deny updates  received from eBGP peers that do not list their AS number as the first AS in the  AS_PATH attribute.  By default Cisco IOS enforces the first AS in the AS_PATH attribute for all route  advertisements. Review the router configuration to verify that the command no bgp  enforce-first-as is not configured.  router bgp xx  no synchronization  no bgp enforce-first-as  If the router is not configured to reject updates from peers that do not list their AS  number as the first AS in the AS_PATH attribute, this is a finding.",
    remediation: "Configure the router to deny updates received from eBGP peers that do not list their AS  number as the first AS in the AS_PATH attribute.  R1(config)#router bgp xx  R1(config-router)#bgp enforce-first-as     Internal Only - General",
    cci: "CCI-000032",
    expectedState: "Configure the router to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.",
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
