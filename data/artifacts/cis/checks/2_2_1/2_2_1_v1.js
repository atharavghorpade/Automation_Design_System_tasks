var metadata = {
    ruleNumber: "2.2.1",
    title: "Set 'logging enable' (Automated)",
    profile: "• Level 1",
    description: "Enable logging of system messages.",
    rationale: "Logging provides a chronological record of activities on the Cisco device and allows monitoring of both operational and security related events.",
    impact: "Enabling the Cisco IOS 'logging enable' command enforces the monitoring of technology risks for the organizations' network devices.",
    audit: "Perform the following to determine if the feature is enabled: Verify no result returns hostname#show run | i logging host",
    remediation: "Enable system logging. hostname(config)#archive hostname(config-archive)#log config hostname(config-archive-log-cfg)#logging enable hostname(config-archive-log-cfg)#end",
    defaultValue: "Logging is not enabled/",
    expectedState: "Logging is not enabled/",
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

        if (line.indexOf("logging is".toLowerCase()) !== -1) {

            matched = true;
            foundLine = i + 1;

            var numberMatch = line.match(/\d+/);
            var actual = numberMatch ? parseInt(numberMatch[0]) : null;

            pass = true;
        }
    }

    if ("equals:true" === "not_exists") {
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
