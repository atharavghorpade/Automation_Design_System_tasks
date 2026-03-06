var metadata = {
    groupIdNumber: "1.61",
    stigId: "CISC-RT-000590",
    ruleId: "RULE ID: SV-216607r531085",
    groupId: "GROUP ID: V-216607",
    severity: "HIGH",
    description: "The Cisco MPLS router must be configured to use its loopback address as the source  address for LDP peering sessions.  GROUP ID: V-216607  RULE ID: SV-216607r531085",
    rationale: "Using a loopback address as the source address offers a multitude of uses for security,  access, management, and scalability of backbone routers. It is easier to construct  appropriate ingress filters for router management plane traffic destined to the network  management subnet since the source addresses will be from the range used for  loopback interfaces instead of from a larger range of addresses used for physical  interfaces. Log information recorded by authentication and syslog servers will record the  router's loopback address instead of the numerous physical interface addresses.",
    audit: "Review the router configuration to determine if it is compliant with this requirement.  Verify that a loopback address has been configured as shown in the following example:  interface Loopback0  ip address 10.1.1.1 255.255.255.255  By default, routers will use its loopback address for LDP peering. If an address has not  be configured on the loopback interface, it will use its physical interface connecting to  the LDP peer. If the router-id command is specified that overrides this default behavior,  verify that it is a loopback interface as shown in the example below.  mpls ldp router-id Loopback0  If the router is not configured do use its loopback address for LDP peering, this is a  finding.",
    remediation: "Configure the router to use their loopback address as the source address for LDP  peering sessions. As noted in the check content, the default behavior is to use its  loopback address.  R4(config)#mpls ldp router-id lo0     Internal Only - General",
    cci: "CCI-000366",
    expectedState: "Configure the router to use their loopback address as the source address for LDP peering sessions.",
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
