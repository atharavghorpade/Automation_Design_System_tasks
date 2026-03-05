var metadata = {
    ruleNumber: "3.3.3.1",
    title: "Set 'key chain' (Automated)",
    profile: "• Level 2",
    description: "Define an authentication key chain to enable authentication for RIPv2 routing protocols.",
    rationale: "This is part of the routing authentication process.",
    impact: "Organizations should plan and implement enterprise security policies that require rigorous authentication methods for routing protocols. Configuring the proper authentication 'key-chain (name)' for RIPv2 protocols enforces these policies by restricting acceptable authentication between network devices.",
    audit: "Verify the appropriate key chain is defined hostname#sh run | sec key chain",
    remediation: "Establish the key chain. hostname(config)#key chain {<em>rip_key-chain_name</em>}",
    defaultValue: "Not set",
    expectedState: "Not set",
    generatedOn: "2026-03-02",
    generatorVersion: "2.1",
    benchmark: "CIS"
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
