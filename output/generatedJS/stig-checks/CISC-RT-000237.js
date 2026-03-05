var metadata = {
    groupIdNumber: "1.17",
    stigId: "CISC-RT-000237",
    ruleId: "RULE ID: SV-230041r532998",
    groupId: "GROUP ID: V-230041",
    severity: "HIGH",
    description: "The Cisco router must not be configured to use IPv6 Site Local Unicast addresses.  GROUP ID: V-230041  RULE ID: SV-230041r532998",
    rationale: "As currently defined, site local addresses are ambiguous and can be present in multiple  sites. The address itself does not contain any indication of the site to which it belongs.  The use of site-local addresses has the potential to adversely affect network security  through leaks, ambiguity, and potential misrouting as documented in section 2 of  RFC3879. RFC3879 formally deprecates the IPv6 site-local unicast prefix FEC0::/10 as  defined in RFC3513.",
    audit: "Review the router configuration to ensure FEC0::/10 IPv6 addresses are not defined.  If IPv6 Site Local Unicast addresses are defined, this is a finding.",
    remediation: "Configure the router using only authorized IPv6 addresses.",
    cci: "CCI-000366",
    expectedState: "Configure the router using only authorized IPv6 addresses.",
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
