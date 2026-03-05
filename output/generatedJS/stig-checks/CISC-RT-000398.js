var metadata = {
    groupIdNumber: "1.41",
    stigId: "CISC-RT-000398",
    ruleId: "RULE ID: SV-230158r856675",
    groupId: "GROUP ID: V-230158",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop- by-Hop or Destination Option extension header with an undefined option type.  GROUP ID: V-230158  RULE ID: SV-230158r856675",
    rationale: "The optional and extensible natures of the IPv6 extension headers require higher  scrutiny since many implementations do not always drop packets with headers that it  cannot recognize, and hence could cause a Denial-of-Service on the target device. In  addition, the type, length, value (TLV) formatting provides the ability for headers to be  very large.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration and determine if filters are bound to the applicable  interfaces to drop all inbound IPv6 packets containing an undefined option type value  regardless of whether they appear in a Hop-by-Hop or Destination Option header.  Undefined values are 0x02, 0x03, 0x06, 0x9 – 0xE, 0x10 – 0x22, 0x24, 0x25, 0x27 –  0x2F, and 0x31 – 0xFF.  Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.  interface gigabitethernet1/0  ipv6 address 2001::1:0:22/64  ipv6 traffic-filter FILTER_IPV6 in  Step 2: Verify that the ACL drops IPv6 packets containing a Hop-by-Hop or Destination  Option extension header with an undefined option type as shown in the example below.  ipv6 access-list FILTER_IPV6  deny any any dest-option-type 2  deny any any dest-option-type 3  deny any any dest-option-type 6  deny any any dest-option-type 9  deny any any dest-option-type 10  deny any any dest-option-type 11  deny any any dest-option-type 12  deny any any dest-option-type 13  deny any any dest-option-type 14  deny any any dest-option-type 16  …  deny any any dest-option-type 34  deny any any dest-option-type 36  deny any any dest-option-type 37  deny any any dest-option-type 39  …  deny any any dest-option-type 47  deny any any dest-option-type 49  …  deny any any dest-option-type 255  permit …  …  …  …  deny ipv6 any any log  Note: Because hop-by-hop and destination options have the same exact header format,  they can be combined under the dest-option-type keyword. Since Hop-by-Hop and  Destination Option headers have non-overlapping types, you can use dest-option-type  to match either.  If the router is not configured to drop IPv6 packets containing a Hop-by-Hop or  Destination Option extension header with an undefined option type, this is a finding.  Internal Only - General",
    remediation: "Configure the router to drop all inbound IPv6 packets containing an undefined option  type value regardless of whether they appear in a Hop-by-Hop or Destination Option  header as shown in the example below.  R1(config)#ipv6 access-list FILTER_IPV6  R1(config-ipv6-acl)#deny any any dest-option-type 2  R1(config-ipv6-acl)#deny any any dest-option-type 3  R1(config-ipv6-acl)#deny any any dest-option-type 6  R1(config-ipv6-acl)#deny any any dest-option-type 9  R1(config-ipv6-acl)#deny any any dest-option-type 10  R1(config-ipv6-acl)#deny any any dest-option-type 11  R1(config-ipv6-acl)#deny any any dest-option-type 12  R1(config-ipv6-acl)#deny any any dest-option-type 13  R1(config-ipv6-acl)#deny any any dest-option-type 14  R1(config-ipv6-acl)#deny any any dest-option-type 16  …  R1(config-ipv6-acl)#deny any any dest-option-type 34  R1(config-ipv6-acl)#deny any any dest-option-type 36  R1(config-ipv6-acl)#deny any any dest-option-type 37  R1(config-ipv6-acl)#deny any any dest-option-type 39  …  R1(config-ipv6-acl)#deny any any dest-option-type 47  R1(config-ipv6-acl)#deny any any dest-option-type 49  …  R1(config-ipv6-acl)#deny any any dest-option-type 255  R1(config-ipv6-acl)#permit …  …  …  …  R1(config-ipv6-acl)#deny ipv6 any any log  R1(config-ipv6-acl)#exit  R1(config)#int g1/0  R1(config-if)#ipv6 traffic-filter FILTER_IPV6",
    cci: "CCI-002403",
    expectedState: "Configure the router to drop all inbound IPv6 packets containing an undefined option type value regardless of whether they appear in a Hop-by-Hop or Destination Option header as shown in the example below.",
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
