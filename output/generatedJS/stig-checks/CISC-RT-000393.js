var metadata = {
    groupIdNumber: "1.36",
    stigId: "CISC-RT-000393",
    ruleId: "RULE ID: SV-230050r856665",
    groupId: "GROUP ID: V-230050",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured drop IPv6 packets with a Routing  Header type 0, 1, or 3–255.  GROUP ID: V-230050  RULE ID: SV-230050r856665",
    rationale: "The routing header can be used maliciously to send a packet through a path where less  robust security is in place, rather than through the presumably preferred path of routing  protocols. Use of the routing extension header has few legitimate uses other than as  implemented by Mobile IPv6.  The Type 0 Routing Header (RFC 5095) is dangerous because it allows attackers to  spoof source addresses and obtain traffic in response, rather than the real owner of the  address. Secondly, a packet with an allowed destination address could be sent through  a Firewall using the Routing Header functionality, only to bounce to a different node  once inside. The Type 1 Routing Header is defined by a specification called \"Nimrod  Routing\", a discontinued project funded by DARPA. Assuming that most  implementations will not recognize the Type 1 Routing Header, it must be dropped. The  Type 3–255 Routing Header values in the routing type field are currently undefined and  should be dropped inbound and outbound.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if it is configured to drop IPv6 packets  containing a Routing Header of type 0, 1, or 3-255.  Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.  interface gigabitethernet1/0  ipv6 address 2001::1:0:22/64  ipv6 traffic-filter FILTER_IPV6 in  Step 2: Verify that the ACL drops IPv6 packets with a Routing Header type 0, 1, or 3- 255 as shown in the example below.  ipv6 access-list FILTER_IPV6  permit ipv6 any host 2001:DB8::1:1:1234 routing-type 2  deny ipv6 any any log routing  permit ipv6 …  …  …  …  deny ipv6 any any log  Note: The example above allows routing-type 2 in the event Mobility IPv6 is deployed.  If the router is not configured to drop IPv6 packets containing a Routing Header of type  0, 1, or 3-255, this is a finding.",
    remediation: "Configure the router to drop IPv6 packets with Routing Header of type 0, 1, or 3-255 as  shown in the example below.  R1(config)#ipv6 access-list FILTER_IPV6  R1(config-ipv6-acl)#permit ipv6 any host 2001:DB8::0:1:1:1234 routing-type 2  R1(config-ipv6-acl)#deny ipv6 any any routing log  R1(config-ipv6-acl)#permit …  …  …  …  R1(config-ipv6-acl)#deny ipv6 any any log  R1(config-ipv6-acl)#exit  R1(config)#int g1/0  R1(config-if)#ipv6 traffic-filter FILTER_IPV6",
    cci: "CCI-002403",
    expectedState: "Configure the router to drop IPv6 packets with Routing Header of type 0, 1, or 3-255 as shown in the example below.",
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
