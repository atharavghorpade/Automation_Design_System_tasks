var metadata = {
    groupIdNumber: "1.88",
    stigId: "CISC-RT-000910",
    ruleId: "RULE ID: SV-216634r856202",
    groupId: "GROUP ID: V-216634",
    severity: "HIGH",
    description: "The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to  authenticate all received MSDP packets.  GROUP ID: V-216634  RULE ID: SV-216634r856202",
    rationale: "MSDP peering with customer network routers presents additional risks to the core,  whether from a rogue or misconfigured MSDP-enabled router. MSDP password  authentication is used to validate each segment sent on the TCP connection between  MSDP peers, protecting the MSDP session against the threat of spoofed packets being  injected into the TCP connection stream.",
    audit: "Review the router configuration to determine if received MSDP packets are  authenticated.  ip msdp peer x.1.28.8 remote-as 8  ip msdp password peer x.1.28.8 xxxxxxxxxxxx  If the router does not require MSDP authentication, this is a finding.",
    remediation: "Configure the router to authenticate MSDP messages as shown in the following  example:  R2(config)#ip msdp password peer x.1.28.8 xxxxxxxxxxxx",
    cci: "CCI-001958",
    expectedState: "Configure the router to authenticate MSDP messages as shown in the following example: R2(config)#ip msdp password peer x.1.28.8 xxxxxxxxxxxx",
    generatedOn: "2026-03-06",
    generatorVersion: "2.0",
    benchmark: "STIG"
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

        if (line.indexOf("ip msdp".toLowerCase()) !== -1) {

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
