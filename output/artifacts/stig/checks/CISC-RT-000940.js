var metadata = {
    groupIdNumber: "1.91",
    stigId: "CISC-RT-000940",
    ruleId: "RULE ID: SV-216637r531085",
    groupId: "GROUP ID: V-216637",
    severity: "HIGH",
    description: "The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to  limit the amount of source-active messages it accepts on a per-peer basis.  GROUP ID: V-216637  RULE ID: SV-216637r531085",
    rationale: "To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured  MSDP router, the router must be configured to limit the number of source-active  messages it accepts from each peer.",
    audit: "Review the router configuration to determine if it is configured to limit the amount of  source-active messages it accepts on a per-peer basis.  ip msdp peer x.1.28.2 remote-as nn  ip msdp sa-filter in 10.1.28.2 list MSDP_SA_FILTER  ip msdp sa-limit X.1.28.2 nnn  If the router is not configured to limit the source-active messages it accepts, this is a  finding.",
    remediation: "Configure the router to limit the amount of source-active messages it accepts from each  peer.  R8(config)#ip msdp sa-limit x.1.28.2 nnn",
    cci: "CCI-001368",
    expectedState: "Configure the router to limit the amount of source-active messages it accepts from each peer.",
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
