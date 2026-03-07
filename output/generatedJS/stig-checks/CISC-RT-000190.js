var metadata = {
    groupIdNumber: "1.10",
    stigId: "CISC-RT-000190",
    ruleId: "SV-216567r856186",
    groupId: "V-216567",
    severity: "HIGH",
    description: "The Cisco router must be configured to have Internet Control Message Protocol (ICMP)  redirect messages disabled on all external interfaces.  GROUP ID: V-216567  RULE ID: SV-216567r856186",
    rationale: "The ICMP supports IP traffic by relaying information about paths, routes, and network  conditions. Routers automatically send ICMP messages under a wide variety of  conditions. Redirect ICMP messages are commonly used by attackers for network  mapping and diagnosis.",
    audit: "Review the router configuration to verify that the no ip redirects command has been  configured on all external interfaces as shown in the example below.  interface GigabitEthernet0/1  ip address x.x.x.x 255.255.255.0  no ip redirects  If ICMP Redirect messages are enabled on any external interfaces, this is a finding.",
    remediation: "Disable ICMP redirects on all external interfaces as shown in the example below.  R4(config)#int g0/1  R4(config-if)#no ip redirects",
    cci: "CCI-002385",
    expectedState: "Disable ICMP redirects on all external interfaces as shown in the example below.",
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
