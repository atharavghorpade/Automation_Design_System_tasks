var metadata = {
    groupIdNumber: "1.68",
    stigId: "CISC-RT-000660",
    ruleId: "RULE ID: SV-216614r864155",
    groupId: "GROUP ID: V-216614",
    severity: "HIGH",
    description: "The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services  must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions  used to exchange virtual circuit (VC) information using a FIPS-approved message  authentication code algorithm.  GROUP ID: V-216614  RULE ID: SV-216614r864155",
    rationale: "LDP provides the signaling required for setting up and tearing down pseudowires  (virtual circuits used to transport Layer 2 frames) across an MPLS IP core network.  Using a targeted LDP session, each PE router advertises a virtual circuit label mapping  that is used as part of the label stack imposed on the frames by the ingress PE router  during packet forwarding. Authentication provides protection against spoofed TCP  segments that can be introduced into the LDP sessions.",
    audit: "The Cisco router is not compliant with this requirement; hence, it is a finding. However,  the severity level can be mitigated to a category 3 if the router is configured to  authenticate targeted LDP sessions using MD5 as shown in the configuration example  below.  mpls ldp neighbor 10.1.1.2 password xxxxxxx  mpls label protocol ldp  If the router is not configured to authenticate targeted LDP sessions using MD5, the  finding will remain as a category 2.",
    remediation: "The severity level can be downgraded to a category 3 if the router is configured to  authenticate targeted LDP sessions using MD5 as shown in the example below.  R5(config)#mpls ldp neighbor 10.1.1.2 password xxxxxxxx",
    cci: "CCI-001958",
    expectedState: "The severity level can be downgraded to a category 3 if the router is configured to authenticate targeted LDP sessions using MD5 as shown in the example below.",
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
