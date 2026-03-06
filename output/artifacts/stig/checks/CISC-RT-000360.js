var metadata = {
    groupIdNumber: "1.30",
    stigId: "CISC-RT-000360",
    ruleId: "RULE ID: SV-216584r856189",
    groupId: "GROUP ID: V-216584",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to have Link Layer Discovery Protocol  (LLDP) disabled on all external interfaces.  GROUP ID: V-216584  RULE ID: SV-216584r856189",
    rationale: "LLDP is a neighbor discovery protocol used to advertise device capabilities,  configuration information, and device identity. LLDP is media- and protocol-independent  as it runs over layer 2; therefore, two network nodes that support different layer 3  protocols can still learn about each other. Allowing LLDP messages to reach external  network nodes provides an attacker a method to obtain information of the network  infrastructure that can be useful to plan an attack.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Step 1: Verify LLDP is not enabled globally via the command  lldp run  By default LLDP is not enabled globally. If LLDP is enabled, proceed to step 2.  Step 2: Verify LLDP is not enabled on any external interface as shown in the example  below.  interface GigabitEthernet0/1  ip address x.1.12.1 255.255.255.252  no lldp transmit  Note: LLDP is enabled by default on all interfaces once it is enabled globally; hence the  command lldp transmit will not be visible on the interface configuration.  If LLDP transmit is enabled on any external interface, this is a finding.",
    remediation: "Disable LLDP transmit on all external interfaces as shown in the example below.  R5(config)#int g0/1  R5(config-if)#no lldp transmit     Internal Only - General",
    cci: "CCI-002403",
    expectedState: "Disable LLDP transmit on all external interfaces as shown in the example below.",
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
