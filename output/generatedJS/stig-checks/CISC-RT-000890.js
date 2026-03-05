var metadata = {
    groupIdNumber: "1.86",
    stigId: "CISC-RT-000890",
    ruleId: "RULE ID: SV-216632r856200",
    groupId: "GROUP ID: V-216632",
    severity: "HIGH",
    description: "The Cisco multicast Designated Router (DR) must be configured to set the shortest- path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the  multicast topology where Any Source Multicast (ASM) is deployed.  GROUP ID: V-216632  RULE ID: SV-216632r856200",
    rationale: "ASM can have many sources for the same groups (many-to-many). For many receivers,  the path via the RP may not be ideal compared with the shortest path from the source to  the receiver. By default, the last-hop router will initiate a switch from the shared tree to a  source-specific SPT to obtain lower latencies. This is accomplished by the last-hop  router sending an (S, G) Protocol Independent Multicast (PIM) Join toward S (the  source).  When the last-hop router begins to receive traffic for the group from the source via the  SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a  Prune message toward the source. The SPT switchover becomes a scaling issue for  large multicast topologies that have many receivers and many sources for many groups  because (S, G) entries require more memory than (*, G). Hence, it is imperative to  minimize the amount of (S, G) state to be maintained by increasing the threshold that  determines when the SPT switchover occurs.",
    audit: "Review the DR configuration to verify that the SPT switchover threshold is increased  (default is \"0\") or set to infinity (never switch over).  ip pim rp-address 10.2.2.2  ip pim spt-threshold infinity  If the DR is not configured to increase the SPT threshold or set to infinity to minimalize  (S, G) state, this is a finding.",
    remediation: "Configure the DR to increase the SPT threshold or set it to infinity to minimalize (S, G)  state within the multicast topology where ASM is deployed.  R3(config)#ip pim spt-threshold infinity  Internal Only - General",
    cci: "CCI-002385",
    expectedState: "Configure the DR to increase the SPT threshold or set it to infinity to minimalize (S, G) state within the multicast topology where ASM is deployed.",
    generatedOn: "2026-03-02",
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
