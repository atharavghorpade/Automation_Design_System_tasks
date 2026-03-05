var metadata = {
    groupIdNumber: "1.85",
    stigId: "CISC-RT-000880",
    ruleId: "RULE ID: SV-216631r856199",
    groupId: "GROUP ID: V-216631",
    severity: "HIGH",
    description: "The Cisco multicast Designated Router (DR) must be configured to limit the number of  mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast  Listener Discovery (MLD) Host Membership Reports.  GROUP ID: V-216631  RULE ID: SV-216631r856199",
    rationale: "The current multicast paradigm can let any host join any multicast group at any time by  sending an IGMP or MLD membership report to the DR. In a Protocol Independent  Multicast (PIM) Sparse Mode network, the DR will send a PIM Join message for the  group to the RP. Without any form of admission control, this can pose a security risk to  the entire multicast domain - specifically the multicast routers along the shared tree from  the DR to the RP that must maintain the mroute state information for each group join  request. Hence, it is imperative that the DR is configured to limit the number of mroute  state information that must be maintained to mitigate the risk of IGMP or MLD flooding.",
    audit: "Review the DR configuration to verify that it is limiting the number of mroute states via  IGMP or MLD.  Verify IGMP limits have been configured globally or on each host-facing interface via  the ip igmp limit command as shown in the example.  interface GigabitEthernet0/0  ip address 10.3.3.3 255.255.255.0  …  …  …  ip igmp limit nn  If the DR is not limiting multicast join requests via IGMP or MLD on a global or  interfaces basis, this is a finding.",
    remediation: "Configure the DR on a global or interface basis to limit the number of mroute states  resulting from IGMP or MLD membership reports.  R3(config)#int g0/0  R3(config-if)#ip igmp limit 2  Internal Only - General",
    cci: "CCI-002385",
    expectedState: "Configure the DR on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.",
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

        if (line.indexOf("interface basis".toLowerCase()) !== -1) {

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
