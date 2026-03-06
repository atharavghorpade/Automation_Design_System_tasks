var metadata = {
    groupIdNumber: "1.62",
    stigId: "CISC-RT-000600",
    ruleId: "RULE ID: SV-216608r531085",
    groupId: "GROUP ID: V-216608",
    severity: "HIGH",
    description: "The Cisco MPLS router must be configured to synchronize IGP and LDP to minimize  packet loss when an IGP adjacency is established prior to LDP peers completing label  exchange.  GROUP ID: V-216608  RULE ID: SV-216608r531085",
    rationale: "Packet loss can occur when an IGP adjacency is established and the router begins  forwarding packets using the new adjacency before the LDP label exchange completes  between the peers on that link. Packet loss can also occur if an LDP session closes and  the router continues to forward traffic using the link associated with the LDP peer rather  than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP  Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to  minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP- IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric  on that link.",
    audit: "Review the router OSPF or IS-IS configuration and verify that LDP will synchronize with  the link-state routing protocol as shown in the example below.  OSPF Example  router ospf 1  mpls ldp sync  IS-IS Example  router isis  mpls ldp sync  net 49.0001.1234.1600.5531.00  If the router is not configured to synchronize IGP and LDP, this is a finding.  Internal Only - General",
    remediation: "Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when  an IGP adjacency is established prior to LDP peers completing label exchange.  OSPF Example  R2(config)#router ospf 1  R2(config-router)#mpls ldp sync  IS-IS Example  R5(config)#router isis  R5(config-router)#mpls ldp sync",
    cci: "CCI-000366",
    expectedState: "Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.",
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
