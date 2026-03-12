var metadata = {
    groupIdNumber: "1.65",
    stigId: "CISC-RT-000630",
    ruleId: "SV-216611r531085",
    groupId: "V-216611",
    severity: "HIGH",
    description: "The Cisco PE router must be configured to have each Virtual Routing and Forwarding  (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic  separation between all MPLS L3VPNs.  GROUP ID: V-216611  RULE ID: SV-216611r531085",
    rationale: "The primary security model for an MPLS L3VPN infrastructure is traffic separation. The  service provider must guarantee the customer that traffic from one VPN does not leak  into another VPN or into the core, and that core traffic must not leak into any VPN.  Hence, it is imperative that each CE-facing interface can only be associated to one  VRF—that alone is the fundamental framework for traffic separation.",
    audit: "Step 1: Review the design plan for deploying MPLS/L3VPN.  Step 2: Review all CE-facing interfaces and verify that the proper VRF is defined via the  \"ip vrf forwarding\" command. In the example below, COI1 is bound to interface  GigabitEthernet0/1, while COI2 is bound to GigabitEthernet0/2.  interface GigabitEthernet0/1  description link to COI1  ip vrf forwarding COI1  ip address x.1.0.1 255.255.255.0  !  interface GigabitEthernet0/2  description link to COI2  ip vrf forwarding COI2  ip address x.2.0.2 255.255.255.0  If any VRFs are not bound to the appropriate physical or logical interface, this is a  finding.",
    remediation: "Configure the PE router to have each VRF bound to the appropriate physical or logical  interfaces to maintain traffic separation between all MPLS L3VPNs.     Internal Only - General",
    cci: "CCI-000366",
    expectedState: "Configure the PE router to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.",
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
