var metadata = {
    groupIdNumber: "1.84",
    stigId: "CISC-RT-000870",
    ruleId: "RULE ID: SV-216630r864158",
    groupId: "GROUP ID: V-216630",
    severity: "HIGH",
    description: "The Cisco multicast Designated Router (DR) must be configured to filter the Internet  Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report  messages to allow hosts to join a multicast group only from sources that have been  approved by the organization.  GROUP ID: V-216630  RULE ID: SV-216630r864158",
    rationale: "Real-time multicast traffic can entail multiple large flows of data. Large unicast flows  tend to be fairly isolated (i.e., someone doing a file download here or there), whereas  multicast can have broader impact on bandwidth consumption, resulting in extreme  network congestion. Hence, it is imperative that there is multicast admission control to  restrict which multicast groups hosts are allowed to join via IGMP or MLD.",
    audit: "Review the configuration of the DR to verify that it is filtering IGMP or MLD report  messages, allowing hosts to only join multicast groups from sources that have been  approved.  Step 1: Verify that all host-facing interfaces are configured to filter IGMP Membership  Report messages (IGMP joins) as shown in the example below.  interface GigabitEthernet0/0  ip address 10.3.3.3 255.255.255.0  ip pim sparse-mode  ip igmp access-group IGMP_JOIN_FILTER  ip igmp version 3  Step 2: Verify that the Access Control List (ACL) denies unauthorized sources or allows  only authorized sources. The example below denies all groups from 232.8.0.0/16 range  and permits sources only from the x.0.0.0/8 network.  ip access-list extended IGMP_JOIN_FILTER  deny ip any 232.8.0.0 0.0.255.255  permit ip x.0.0.0 0.255.255.255 any  deny ip any any  Note: This requirement is only applicable to Source Specific Multicast (SSM)  implementation.  If the DR is not filtering IGMP or MLD report messages, this is a finding.  Internal Only - General",
    remediation: "Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only  those multicast groups from sources that have been approved as shown in the example.  R3(config)#ip access-list extended IGMP_JOIN_FILTER  R3(config-ext-nacl)#deny ip any 232.8.0.0 0.0.255.255  R3(config-ext-nacl)#permit ip x.0.0.0 0.255.255.255 any  R3(config-ext-nacl)#deny ip any any  R3(config-ext-nacl)#exit  Step 2: Apply the filter to all host facing interfaces.  R3(config)#int g0/0  R3(config-if)#ip igmp access-group IGMP_JOIN_FILTER",
    cci: "CCI-002403",
    expectedState: "Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only those multicast groups from sources that have been approved as shown in the example.",
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
