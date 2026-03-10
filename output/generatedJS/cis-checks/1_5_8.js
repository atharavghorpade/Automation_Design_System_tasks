var metadata = {
    ruleNumber: "1.5.8",
    title: "Set 'snmp-server enable traps snmp' (Automated)",
    profile: "• Level 1",
    description: "SNMP notifications can be sent as traps to authorized management systems.",
    rationale: "SNMP has the ability to submit traps .",
    impact: "Organizations using SNMP should restrict trap types only to explicitly named traps to reduce unintended traffic. Enabling SNMP traps without specifying trap type will enable all SNMP trap types.",
    audit: "Perform the following to determine if SNMP traps are enabled: If the command returns configuration values, then SNMP is enabled. hostname#show run | incl snmp-server",
    remediation: "Enable SNMP traps. hostname(config)#snmp-server enable traps snmp authentication linkup linkdown coldstart",
    defaultValue: "SNMP notifications are disabled.",
    expectedState: "SNMP notifications are disabled.",
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

    if ("equals:false" === "not_exists") {
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
