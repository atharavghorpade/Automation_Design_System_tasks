var metadata = {
    groupIdNumber: "1.35",
    stigId: "CISC-RT-000392",
    ruleId: "RULE ID: SV-230047r856663",
    groupId: "GROUP ID: V-230047",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to drop IPv6 undetermined transport  packets.  GROUP ID: V-230047  RULE ID: SV-230047r856663",
    rationale: "One of the fragmentation weaknesses known in IPv6 is the undetermined transport  packet. This packet contains an undetermined protocol due to fragmentation.  Depending on the length of the IPv6 extension header chain, the initial fragment may  not contain the layer four port information of the packet.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if it is configured to drop IPv6  undetermined transport packets.  Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.  interface gigabitethernet1/0  ipv6 address 2001::1:0:22/64  ipv6 traffic-filter FILTER_IPV6 in  Step 2: Verify that the ACL drops undetermined transport packets as shown in the  example below.  ipv6 access-list FILTER_IPV6  deny ipv6 any any log undetermined-transport  permit ipv6 …  …  …  …  deny ipv6 any any log  If the router is not configured to drop IPv6 undetermined transport packets, this is a  finding.  Internal Only - General",
    remediation: "Configure the router to drop IPv6 undetermined transport packets as shown in the  example below.  R1(config)#ipv6 access-list FILTER_IPV6  R1(config-ipv6-acl)#deny ipv6 any any undetermined-transport log  R1(config-ipv6-acl)#permit ipv6 …  …  …  …  R1(config-ipv6-acl)#deny ipv6 any any log  R1(config-ipv6-acl)#exit  R1(config)#int g1/0  R1(config-if)#ipv6 traffic-filter FILTER_IPV6 in",
    cci: "CCI-002403",
    expectedState: "Configure the router to drop IPv6 undetermined transport packets as shown in the example below.",
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
