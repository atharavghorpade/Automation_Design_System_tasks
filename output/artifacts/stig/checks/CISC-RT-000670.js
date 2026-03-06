var metadata = {
    groupIdNumber: "1.69",
    stigId: "CISC-RT-000670",
    ruleId: "RULE ID: SV-216615r531085",
    groupId: "GROUP ID: V-216615",
    severity: "HIGH",
    description: "The Cisco PE router providing MPLS Virtual Private Wire Service (VPWS) must be  configured to have the appropriate virtual circuit identification (VC ID) for each  attachment circuit.  GROUP ID: V-216615  RULE ID: SV-216615r531085",
    rationale: "VPWS is an L2VPN technology that provides a virtual circuit between two PE routers to  forward Layer 2 frames between two customer-edge routers or switches through an  MPLS-enabled IP core. The ingress PE router (virtual circuit head-end) encapsulates  Ethernet frames inside MPLS packets using label stacking and forwards them across  the MPLS network to the egress PE router (virtual circuit tail-end). During a virtual circuit  setup, the PE routers exchange VC label bindings for the specified VC ID. The VC ID  specifies a pseudowire associated with an ingress and egress PE router and the  customer-facing attachment circuits.  To guarantee that all frames are forwarded onto the correct pseudowire and to the  correct customer and attachment circuits, it is imperative that the correct VC ID is  configured for each attachment circuit.",
    audit: "Verify that the correct and unique VCID has been configured for the appropriate  attachment circuit. In the example below GigabitEthernet0/1 is the CE-facing interface  that is configured for VPWS with the VCID of 55.  interface GigabitEthernet0/1  xconnect x.2.2.12 55 encapsulation mpls  If the correct VC ID has not been configured on both routers, this is a finding.",
    remediation: "Assign globally unique VC IDs for each virtual circuit and configure the attachment  circuits with the appropriate VC ID.  R5(config)#int g0/1  R5(config-if)#xconnect x.2.2.12 55 encapsulation mpls     Internal Only - General",
    cci: "CCI-000366",
    expectedState: "Assign globally unique VC IDs for each virtual circuit and configure the attachment circuits with the appropriate VC ID.",
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
