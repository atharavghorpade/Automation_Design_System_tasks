var metadata = {
    ruleNumber: "2.2.3",
    title: "Set 'logging console critical' (Automated)",
    profile: "• Level 1",
    description: "Verify logging to device console is enabled and limited to a rational severity level to avoid impacting system performance and management.",
    rationale: "This configuration determines the severity of messages that will generate console messages. Logging to console should be limited only to those messages required for immediate troubleshooting while logged into the device. This form of logging is not persistent; messages printed to the console are not stored by the router. Console logging is handy for operators when they use the console.",
    impact: "Logging critical messages at the console is important for an organization managing technology risk. The 'logging console' command should capture appropriate severity messages to be effective.",
    audit: "Perform the following to determine if the feature is enabled: Verify a command string result returns hostname#show run | incl logging console",
    remediation: "Configure console logging level. hostname(config)#logging console critical",
    defaultValue: "Tthe default is to log all messages Additional Information: The console is a slow display device. In message storms some logging messages may be silently dropped when the console queue becomes full. Set severity levels accordingly. Page 138 CIS Controls: Controls Version Control IG 1 IG 2 IG 3 v8",
    expectedState: "Set severity levels accordingly.",
    generatedOn: "2026-03-06",
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
