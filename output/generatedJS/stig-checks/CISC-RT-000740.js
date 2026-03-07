var metadata = {
    groupIdNumber: "1.71",
    stigId: "CISC-RT-000740",
    ruleId: "SV-216617r531085",
    groupId: "V-216617",
    severity: "HIGH",
    description: "The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF)  loose mode enabled on all CE-facing interfaces.  GROUP ID: V-216617  RULE ID: SV-216617r531085",
    rationale: "The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by  verifying if the source address of any ingress packet is reachable. To mitigate attacks  that rely on forged source addresses, all provider edge routers must enable uRPF loose  mode to guarantee that all packets received from a CE router contain source addresses  that are in the route table.",
    audit: "Review the router configuration to determine if uRPF loose mode is enabled on all CE- facing interfaces.  interface GigabitEthernet0/2  ip address x.1.12.2 255.255.255.252  ip access-group BLOCK_TO_CORE in  ip verify unicast source reachable-via any  If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.",
    remediation: "Configure uRPF loose mode on all CE-facing interfaces as shown in the example  below.  R2(config)#int R4(config)#int g0/2  R2(config-if)#ip verify unicast source reachable-via any  R2(config-if)#end",
    cci: "CCI-001097",
    expectedState: "Configure uRPF loose mode on all CE-facing interfaces as shown in the example below.",
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
