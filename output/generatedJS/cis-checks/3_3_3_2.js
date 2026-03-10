var metadata = {
    ruleNumber: "3.3.3.2",
    title: "Set 'key' (Automated)",
    profile: "• Level 2",
    description: "Configure an authentication key on a key chain.",
    rationale: "This is part of the routing authentication setup",
    impact: "Organizations should plan and implement enterprise security policies that require rigorous authentication methods for routing protocols. Configuring the proper authentication 'key' for RIPv2 protocols enforces these policies by restricting acceptable authentication between network devices.",
    audit: "Verify the appropriate key chain is defined hostname#sh run | sec key chain",
    remediation: "Configure the key number. hostname(config-keychain)#key {<em>key-number</em>}",
    defaultValue: "",
    expectedState: "Configure the key number.",
    generatedOn: "2026-03-09",
    generatorVersion: "2.1",
    benchmark: "CIS"
};
// -----------------------------------------------------------

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
