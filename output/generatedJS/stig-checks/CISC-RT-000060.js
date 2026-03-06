var metadata = {
    groupIdNumber: "1.3",
    stigId: "CISC-RT-000060",
    ruleId: "RULE ID: SV-216556r531085",
    groupId: "GROUP ID: V-216556",
    severity: "HIGH",
    description: "The Cisco router must be configured to have all inactive interfaces disabled.  GROUP ID: V-216556  RULE ID: SV-216556r531085",
    rationale: "An inactive interface is rarely monitored or controlled and may expose a network to an  undetected attack on that interface. Unauthorized personnel with access to the  communication facility could gain access to a router by connecting to a configured  interface that is not in use.  If an interface is no longer used, the configuration must be deleted and the interface  disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and  delete sub-interfaces that are themselves inactive. If the sub-interface is no longer  necessary for authorized communications, it must be deleted.",
    audit: "Review the router configuration and verify that inactive interfaces have been disabled as  shown below.  interface GigabitEthernet3  shutdown  !  interface GigabitEthernet4  shutdown  If an interface is not being used but is configured or enabled, this is a finding.",
    remediation: "Disable all inactive interfaces as shown below.  R4(config)#interface GigabitEthernet3  R4(config-if)#shutdown  R4(config)#interface GigabitEthernet4  R4(config-if)#shutdown     Internal Only - General",
    cci: "CCI-001414",
    expectedState: "Disable all inactive interfaces as shown below.",
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
