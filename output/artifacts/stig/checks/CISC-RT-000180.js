var metadata = {
    groupIdNumber: "1.9",
    stigId: "CISC-RT-000180",
    ruleId: "RULE ID: SV-216566r856185",
    groupId: "GROUP ID: V-216566",
    severity: "HIGH",
    description: "The Cisco router must be configured to have Internet Control Message Protocol (ICMP)  mask reply messages disabled on all external interfaces.  GROUP ID: V-216566  RULE ID: SV-216566r856185",
    rationale: "The ICMP supports IP traffic by relaying information about paths, routes, and network  conditions. Routers automatically send ICMP messages under a wide variety of  conditions. Mask Reply ICMP messages are commonly used by attackers for network  mapping and diagnosis.",
    audit: "Review the router configuration and verify that ip mask-reply command is not enabled  on any external interfaces as shown in the example below.  interface GigabitEthernet0/1  ip address x.x.x.x 255.255.255.0  ip mask-reply  If the ip mask-reply command is configured on any external interface, this is a finding.",
    remediation: "Disable ip mask-reply on all external interfaces as shown below.  R4(config)#int g0/1  R4(config-if)#no ip mask-reply",
    cci: "CCI-002385",
    expectedState: "Disable ip mask-reply on all external interfaces as shown below.",
    generatedOn: "2026-03-06",
    generatorVersion: "2.1",
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

        if (line.indexOf("ip mask-reply".toLowerCase()) !== -1) {

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
