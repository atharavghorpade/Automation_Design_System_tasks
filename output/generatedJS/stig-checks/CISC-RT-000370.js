var metadata = {
    groupIdNumber: "1.31",
    stigId: "CISC-RT-000370",
    ruleId: "RULE ID: SV-216585r856190",
    groupId: "GROUP ID: V-216585",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP)  disabled on all external interfaces.  GROUP ID: V-216585  RULE ID: SV-216585r856190",
    rationale: "CDP is a Cisco proprietary neighbor discovery protocol used to advertise device  capabilities, configuration information, and device identity. CDP is media- and protocol- independent as it runs over layer 2; therefore, two network nodes that support different  layer 3 protocols can still learn about each other. Allowing CDP messages to reach  external network nodes provides an attacker a method to obtain information of the  network infrastructure that can be useful to plan an attack.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Step 1: Verify CDP is not enabled globally via the command no cdp run  By default CDP is enabled globally; hence, the command cdp run will not be shown in  the configuration. If CDP is enabled, proceed to step 2.  Step 2: Verify CDP is not enabled on any external interface as shown in the example  below.  interface GigabitEthernet0/1  ip address x.1.23.2 255.255.255.252  no cdp enable  Note: By default CDP is enabled on all interfaces if CDP is enabled globally.  If CDP is enabled on any external interface, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Disable CDP on all external interfaces via no cdp enable command or disable CDP  globally via no cdp run command.",
    cci: "CCI-002403",
    expectedState: "Disable CDP on all external interfaces via no cdp enable command or disable CDP globally via no cdp run command.",
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

        if (line.indexOf("no cdp".toLowerCase()) !== -1) {

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
