var metadata = {
    groupIdNumber: "1.39",
    stigId: "CISC-RT-000396",
    ruleId: "RULE ID: SV-230152r856671",
    groupId: "GROUP ID: V-230152",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to drop IPv6 packets containing an  extension header with the Endpoint Identification option.  GROUP ID: V-230152  RULE ID: SV-230152r856671",
    rationale: "The optional and extensible natures of the IPv6 extension headers require higher  scrutiny since many implementations do not always drop packets with headers that it  cannot recognize, and hence could cause a Denial-of-Service on the target device. In  addition, the type, length, value (TLV) formatting provides the ability for headers to be  very large. This option type is associated with the Nimrod Routing system and has no  defining RFC document.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if it is compliant with this requirement.  Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.  interface gigabitethernet1/0  ipv6 address 2001::1:0:22/64  ipv6 traffic-filter FILTER_IPV6 in  Step 2: Verify that the ACL drops IPv6 packets containing an extension header with the  Endpoint Identification option as shown in the example below.  ipv6 access-list FILTER_IPV6  deny any any dest-option-type 138 log  permit ipv6 …  …  …  …  deny ipv6 any any log  If the router is not configured to drop IPv6 packets containing an extension header with  the Endpoint Identification option, this is a finding.  Internal Only - General",
    remediation: "Configure the router to drop IPv6 packets containing an option type values of 0x8A  (Endpoint Identification) regardless of whether it appears in a Hop-by-Hop or  Destination Option header as shown in the example below.  R1(config)#ipv6 access-list FILTER_IPV6  R1(config-ipv6-acl)#deny any any dest-option-type 138 log  R1(config-ipv6-acl)#permit ipv6 …  …  …  …  R1(config-ipv6-acl)# deny ipv6 any any log  R1(config-ipv6-acl)#exit  R1(config)#int g1/0  R1(config-if)#ipv6 traffic-filter FILTER_IPV6  R1(config-if)#end",
    cci: "CCI-002403",
    expectedState: "Configure the router to drop IPv6 packets containing an option type values of 0x8A (Endpoint Identification) regardless of whether it appears in a Hop-by-Hop or Destination Option header as shown in the example below.",
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
