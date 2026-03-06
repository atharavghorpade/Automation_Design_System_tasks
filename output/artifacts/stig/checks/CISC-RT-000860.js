var metadata = {
    groupIdNumber: "1.83",
    stigId: "CISC-RT-000860",
    ruleId: "RULE ID: SV-216629r864157",
    groupId: "GROUP ID: V-216629",
    severity: "HIGH",
    description: "The Cisco multicast Designated Router (DR) must be configured to filter the Internet  Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report  messages to allow hosts to join only multicast groups that have been approved by the  organization.  GROUP ID: V-216629  RULE ID: SV-216629r864157",
    rationale: "Real-time multicast traffic can entail multiple large flows of data. Large unicast flows  tend to be fairly isolated (i.e., someone doing a file download here or there), whereas  multicast can have broader impact on bandwidth consumption, resulting in extreme  network congestion. Hence, it is imperative that there is multicast admission control to  restrict which multicast groups hosts are allowed to join via IGMP or MLD.",
    audit: "Review the configuration of the DR to verify that it is filtering IGMP or MLD Membership  Report messages, allowing hosts to join only those groups that have been approved.  Step 1: Verify that all host facing interfaces are configured to filter IGMP Membership  Report messages (IGMP joins) as shown in the example below.  interface GigabitEthernet0/0  ip address 10.3.3.3 255.255.255.0  ip pim sparse-mode  ip igmp access-group IGMP_JOIN_FILTER  ip igmp version 3  Step 2: Verify that the Access Control List (ACL) denies unauthorized groups or permits  only authorized groups. The example below denies all groups from 239.8.0.0/16 range.  ip access-list standard IGMP_JOIN_FILTER  deny 239.8.0.0 0.0.255.255  permit any  Note: This requirement is only applicable to Source Specific Multicast (SSM)  implementation. This requirement is not applicable to Any Source Multicast (ASM) since  the filtering is being performed by the Rendezvous Point router.  If the DR is not filtering IGMP or MLD Membership Report messages, this is a finding.  Internal Only - General",
    remediation: "Configure the DR to filter the IGMP or MLD Membership Report messages to allow  hosts to join only those multicast groups that have been approved.  Step 1: Configure the ACL to filter IGMP Membership Report messages as shown in the  example.  R3(config)#ip access-list standard IGMP_JOIN_FILTER  R3(config-std-nacl)#deny 239.8.0.0 0.0.255.255  R3(config-std-nacl)#permit any  R3(config-std-nacl)#exit  Step 2: Apply the filter to all host facing interfaces.  R3(config)#int g0/0  R3(config-if)#ip igmp access-group IGMP_JOIN_FILTER",
    cci: "CCI-002403",
    expectedState: "Configure the DR to filter the IGMP or MLD Membership Report messages to allow hosts to join only those multicast groups that have been approved.",
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

        if (line.indexOf("ip report".toLowerCase()) !== -1) {

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
