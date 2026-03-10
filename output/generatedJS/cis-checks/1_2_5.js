var metadata = {
    ruleNumber: "1.2.5",
    title: "Set 'access-class' for 'line vty' (Automated)",
    profile: "• Level 1",
    description: "The 'access-class' setting restricts incoming and outgoing connections between a particular vty (into a Cisco device) and the networking devices associated with addresses in an access list.",
    rationale: "Restricting the type of network devices, associated with the addresses on the access- list, further restricts remote access to those devices authorized to manage the device and reduces the risk of unauthorized access.",
    impact: "Applying 'access'class' to line VTY further restricts remote access to only those devices authorized to manage the device and reduces the risk of unauthorized access. Conversely, using VTY lines with 'access class' restrictions increases the risks of unauthorized access.",
    audit: "Perform the following to determine if the ACL is set: Verify you see the access-class defined hostname#sh run | sec vty <line-number> <ending-line-number>",
    remediation: "Configure remote management access control restrictions for all VTY lines. hostname(config)#line vty <line-number> <ending-line-number> hostname(config-line)# access-class <vty_acl_number> in",
    defaultValue: "",
    expectedState: "Configure remote management access control restrictions for all VTY lines.",
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
