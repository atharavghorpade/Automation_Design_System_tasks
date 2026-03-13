var metadata = {
    ruleNumber: "1.5.2",
    title: "Unset 'private' for 'snmp-server community' (Automated)",
    profile: "• Level 1",
    description: "An SNMP community string permits read-only access to all objects.",
    rationale: "The default community string \"private\" is well known. Using easy to guess, well known community string poses a threat that an attacker can effortlessly gain unauthorized access to the device.",
    impact: "To reduce the risk of unauthorized access, Organizations should disable default, easy to guess, settings such as the 'private' setting for snmp-server community.",
    audit: "Perform the following to determine if the public community string is enabled: Ensure private does not show as a result hostname# show snmp community",
    remediation: "Disable the default SNMP community string private hostname(config)#no snmp-server community {private}",
    defaultValue: "",
    expectedState: "Disable the default SNMP community string private hostname(config)#no snmp-server community {private}",
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

        if (line.indexOf("no snmp-server".toLowerCase()) !== -1) {

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
