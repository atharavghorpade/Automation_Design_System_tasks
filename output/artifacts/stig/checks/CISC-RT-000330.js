var metadata = {
    groupIdNumber: "1.27",
    stigId: "CISC-RT-000330",
    ruleId: "RULE ID: SV-216581r531085",
    groupId: "GROUP ID: V-216581",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to filter ingress traffic at the external  interface on an inbound direction.  GROUP ID: V-216581  RULE ID: SV-216581r531085",
    rationale: "Access lists are used to separate data traffic into that which it will route (permitted  packets) and that which it will not route (denied packets). Secure configuration of  routers makes use of access lists for restricting access to services on the router itself as  well as for filtering traffic passing through the router.  Inbound versus Outbound: It should be noted that some operating systems default  access lists are applied to the outbound queue. The more secure solution is to apply the  access list to the inbound queue for three reasons:  • The router can protect itself before damage is inflicted.  • The input port is still known and can be filtered upon.  • It is more efficient to filter packets before routing them.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify that an inbound ACL is configured on all  external interfaces as shown in the example below.  interface GigabitEthernet0/2  ip address x.11.1.2 255.255.255.254  ip access-group EXTERNAL_ACL_INBOUND in  If the router is not configured to filter traffic entering the network at all external interfaces  in an inbound direction, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to use an inbound ACL on all external interfaces as shown in the  example below.  R1(config)#int g0/2  R1(config-if)#ip access-group EXTERNAL_ACL_INBOUND in  Internal Only - General",
    cci: "CCI-001097",
    expectedState: "Configure the router to use an inbound ACL on all external interfaces as shown in the example below.",
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
