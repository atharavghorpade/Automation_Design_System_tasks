var metadata = {
    groupIdNumber: "1.66",
    stigId: "CISC-RT-000640",
    ruleId: "SV-216612r531085",
    groupId: "V-216612",
    severity: "HIGH",
    description: "The Cisco PE router must be configured to have each Virtual Routing and Forwarding  (VRF) instance with the appropriate Route Target (RT).  GROUP ID: V-216612  RULE ID: SV-216612r531085",
    rationale: "The primary security model for an MPLS L3VPN as well as a VRF-lite infrastructure is  traffic separation. Each interface can only be associated to one VRF, which is the  fundamental framework for traffic separation. Forwarding decisions are made based on  the routing table belonging to the VRF. Control of what routes are imported into or  exported from a VRF is based on the RT. It is critical that traffic does not leak from one  COI tenant or L3VPN to another; hence, it is imperative that the correct RT is configured  for each VRF.",
    audit: "Review the design plan for MPLS/L3VPN to determine what RTs have been assigned  for each VRF. Review the router configuration and verify that the correct RT is  configured for each VRF. In the example below, route target 13:13 has been configured  for customer 1.  ip vrf CUST1  rd 13:13  route-target export 13:13  route-target import 13:13  If there are VRFs configured with the wrong RT, this is a finding.",
    remediation: "Configure the router to have each VRF instance defined with the correct RT.  R5(config)#ip vrf CUST1  R5(config-vrf)#route-target import 13:13  R5(config-vrf)#route-target export 13:13  R5(config-vrf)#end     Internal Only - General",
    cci: "CCI-000366",
    expectedState: "Configure the router to have each VRF instance defined with the correct RT.",
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
