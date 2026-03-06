var metadata = {
    groupIdNumber: "1.16",
    stigId: "CISC-RT-000236",
    ruleId: "RULE ID: SV-230038r531386",
    groupId: "GROUP ID: V-230038",
    severity: "HIGH",
    description: "The Cisco router must be configured to advertise a hop limit of at least 32 in Router  Advertisement messages for IPv6 stateless auto-configuration deployments.  GROUP ID: V-230038  RULE ID: SV-230038r531386",
    rationale: "The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in  a Router Advertisement message being used by hosts instead of the standardized  default value. If a very small value was configured and advertised to hosts on the LAN  segment, communications would fail due to the hop limit reaching zero before the  packets sent by a host reached its destination.",
    audit: "Review the router configuration to determine if the hop limit has been configured for  Router Advertisement messages as shown in the example.  ipv6 hop-limit 128  If it has been configured and has not been set to at least 32, it is a finding.",
    remediation: "Configure the router to advertise a hop limit of at least 32 in Router Advertisement  messages.  R1(config)#ipv6 hop-limit 128",
    cci: "CCI-000366",
    expectedState: "Configure the router to advertise a hop limit of at least 32 in Router Advertisement messages.",
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

            pass = (actual !== null && actual >= 32);
        }
    }

    if (">=" === "not_exists") {
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
