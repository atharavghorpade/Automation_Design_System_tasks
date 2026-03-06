var metadata = {
    groupIdNumber: "1.72",
    stigId: "CISC-RT-000750",
    ruleId: "RULE ID: SV-216993r856210",
    groupId: "GROUP ID: V-216993",
    severity: "HIGH",
    description: "The Cisco PE router must be configured to drop all packets with any IP options.  GROUP ID: V-216993  RULE ID: SV-216993r856210",
    rationale: "Packets with IP options are not fast switched and therefore must be punted to the router  processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly  send large streams of packets with IP options. Dropping the packets with IP options  reduces the load of IP options packets on the router. The end result is a reduction in the  effects of the DoS attack on the router and on downstream routers.",
    audit: "Review the router configuration to determine if it will drop all packets with IP options as  shown below.  ip options drop  If the router is not configured to drop all packets with IP options, this is a finding.",
    remediation: "Configure the router to drop all packets with IP options as shown below.  R4(config)#ip options drop",
    cci: "CCI-002403",
    expectedState: "Configure the router to drop all packets with IP options as shown below.",
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

        if (line.indexOf("ip options".toLowerCase()) !== -1) {

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
