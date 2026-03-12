var metadata = {
    ruleNumber: "2.2.5",
    title: "Set 'logging trap informational' (Automated)",
    profile: "• Level 1",
    description: "Limit messages logged to the syslog servers based on severity level informational.",
    rationale: "This determines the severity of messages that will generate simple network management protocol (SNMP) trap and or syslog messages. This setting should be set to either \"debugging\" (7) or \"informational\" (6), but no lower.",
    impact: "Logging is an important process for an organization managing technology risk. The 'logging trap' command sets the severity of messages and enforces the logging process.",
    audit: "Perform the following to determine if a syslog server for SNMP traps is enabled: Verify \"level informational\" returns hostname#sh log | incl trap logging",
    remediation: "Configure SNMP trap and syslog logging level. hostname(config)#logging trap informational",
    defaultValue: "Disabled",
    expectedState: "Disabled",
    generatedOn: "2026-03-12",
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
