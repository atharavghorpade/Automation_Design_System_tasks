var metadata = {
    groupIdNumber: "1.34",
    stigId: "CISC-RT-000391",
    ruleId: "RULE ID: SV-230044r533005",
    groupId: "GROUP ID: V-230044",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to suppress Router Advertisements on  all external IPv6-enabled interfaces.  GROUP ID: V-230044  RULE ID: SV-230044r533005",
    rationale: "Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were  present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts  connected such as the interface connecting to external gateways must be configured to  suppress router advertisements.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify that Router Advertisements are suppressed on  all external IPv6-enabled interfaces as shown in the example below.  interface gigabitethernet1/0  ipv6 address 2001::1:0:22/64  ipv6 nd ra suppress  If the router is not configured to suppress Router Advertisements on all external IPv6- enabled interfaces, this is a finding.",
    remediation: "Configure the router to suppress Router Advertisements on all external IPv6-enabled  interfaces as shown in the example below.  R1(config)#int g1/0  R1(config-if)#ipv6 nd ra suppress  R1(config-if)#end",
    cci: "CCI-000366",
    expectedState: "Configure the router to suppress Router Advertisements on all external IPv6-enabled interfaces as shown in the example below.",
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

            pass = (line.indexOf('no ') !== 0);
        }
    }

    if ("equals:true" === "not_exists") {
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
