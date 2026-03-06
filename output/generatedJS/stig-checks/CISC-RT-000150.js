var metadata = {
    groupIdNumber: "1.6",
    stigId: "CISC-RT-000150",
    ruleId: "RULE ID: SV-216563r856182",
    groupId: "GROUP ID: V-216563",
    severity: "HIGH",
    description: "The Cisco router must be configured to have Gratuitous ARP disabled on all external  interfaces.  GROUP ID: V-216563  RULE ID: SV-216563r856182",
    rationale: "A gratuitous ARP is an ARP broadcast in which the source and destination MAC  addresses are the same. It is used to inform the network about a host IP address. A  spoofed gratuitous ARP message can cause network mapping information to be stored  incorrectly, causing network malfunction.",
    audit: "Review the configuration to determine if gratuitous ARP is disabled. The following  command should not be found in the router configuration:  ip gratuitous-arps  Note: With Cisco IOS, Gratuitous ARP is enabled and disabled globally.  If gratuitous ARP is enabled on any external interface, this is a finding.",
    remediation: "Disable gratuitous ARP as shown in the example below:  R5(config)#no ip gratuitous-arps",
    cci: "CCI-002385",
    expectedState: "Disable gratuitous ARP as shown in the example below: R5(config)#no ip gratuitous-arps",
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

        if (line.indexOf("no ip".toLowerCase()) !== -1) {

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
