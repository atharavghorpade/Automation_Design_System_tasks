var metadata = {
    groupIdNumber: "1.82",
    stigId: "CISC-RT-000850",
    ruleId: "RULE ID: SV-216628r856196",
    groupId: "GROUP ID: V-216628",
    severity: "HIGH",
    description: "The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number  of Protocol Independent Multicast (PIM) Register messages.  GROUP ID: V-216628  RULE ID: SV-216628r856196",
    rationale: "When a new source starts transmitting in a PIM Sparse Mode network, the DR will  encapsulate the multicast packets into register messages and forward them to the RP  using unicast. This process can be taxing on the CPU for both the DR and the RP if the  source is running at a high data rate and there are many new sources starting at the  same time. This scenario can potentially occur immediately after a network failover. The  rate limit for the number of register messages should be set to a relatively low value  based on the known number of multicast sources within the multicast domain.",
    audit: "Review the configuration of the RP to verify that it is rate limiting the number of PIM  register messages.  ip pim rp-address 10.2.2.2  ip pim register-rate-limit nn  If the RP is not limiting PIM register messages, this is a finding.",
    remediation: "Configure the RP to rate limit the number of multicast register messages.  R2(config)#ip pim register-rate-limit nn",
    cci: "CCI-002385",
    expectedState: "Configure the RP to rate limit the number of multicast register messages.",
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
