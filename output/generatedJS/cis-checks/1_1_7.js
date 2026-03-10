var metadata = {
    ruleNumber: "1.1.7",
    title: "Set 'aaa accounting connection' (Automated)",
    profile: "• Level 2",
    description: "Provides information about all outbound connections made from the network access server.",
    rationale: "Authentication, authorization and accounting (AAA) systems provide an authoritative source for managing and monitoring access for devices. Centralizing control improves consistency of access control, the services that may be accessed once authenticated and accountability by tracking services accessed. Additionally, centralizing access control simplifies and reduces administrative costs of account provisioning and de- provisioning, especially when managing a large number of devices. AAA Accounting provides a management and audit trail for user and administrative sessions through RADIUS and TACACS+.",
    impact: "Implementing aaa accounting connection creates accounting records about connections from the network access server. Organizations should regular monitor these connection records for exceptions, remediate issues, and report findings regularly.",
    audit: "Perform the following to determine if aaa accounting for connection is required: Verify a command string result returns hostname#show running-config | incl aaa accounting connection",
    remediation: "Configure AAA accounting for connections. hostname(config)#aaa accounting connection {default | list-name | guarantee- first} {start-stop | stop-only | none} {radius | group group-name}",
    defaultValue: "AAA accounting is not enabled.",
    expectedState: "AAA accounting is not enabled.",
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
