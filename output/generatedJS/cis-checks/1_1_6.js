var metadata = {
    ruleNumber: "1.1.6",
    title: "Set 'aaa accounting' to log all privileged use commands",
    profile: "• Level 2",
    description: "Runs accounting for all commands at the specified privilege level.",
    rationale: "Authentication, authorization and accounting (AAA) systems provide an authoritative source for managing and monitoring access for devices. Centralizing control improves consistency of access control, the services that may be accessed once authenticated and accountability by tracking services accessed. Additionally, centralizing access control simplifies and reduces administrative costs of account provisioning and de- provisioning, especially when managing a large number of devices. AAA Accounting provides a management and audit trail for user and administrative sessions through TACACS+.",
    impact: "Enabling 'aaa accounting' for privileged commands records and sends activity to the accounting servers and enables organizations to monitor and analyze privileged activity.",
    audit: "Perform the following to determine if aaa accounting for commands is required: Verify a command string result returns hostname#show running-config | incl aaa accounting commands",
    remediation: "Configure AAA accounting for commands. hostname(config)#aaa accounting commands 15 {default | list-name | guarantee- first} {start-stop | stop-only | none} {radius | group group-name}",
    defaultValue: "AAA accounting is disabled. Additional Information: Valid privilege level entries are integers from 0 through 15. Page 26 CIS Controls: Controls Version Control IG 1 IG 2 IG 3 v8",
    expectedState: "AAA accounting is disabled.",
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
