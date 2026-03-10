var metadata = {
    ruleNumber: "1.2.2",
    title: "Set 'transport input ssh' for 'line vty' connections",
    profile: "• Level 1",
    description: "Selects the Secure Shell (SSH) protocol.",
    rationale: "Configuring VTY access control restricts remote access to only those authorized to manage the device and prevents unauthorized users from accessing the system.",
    impact: "To reduce risk of unauthorized access, organizations should require all VTY management line protocols to be limited to ssh.",
    audit: "Perform the following to determine if SSH is the only transport method for incoming VTY logins: The result should show only \"ssh\" for \"transport input\" hostname#show running-config | sec vty",
    remediation: "Apply SSH to transport input on all VTY management lines hostname(config)#line vty <line-number> <ending-line-number> hostname(config-line)#transport input ssh",
    defaultValue: "",
    expectedState: "Apply SSH to transport input on all VTY management lines hostname(config)#line vty <line-number> <ending-line-number> hostname(config-line)#transport input ssh",
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
