var metadata = {
    groupIdNumber: "1.64",
    stigId: "CISC-RT-000620",
    ruleId: "SV-216610r531085",
    groupId: "V-216610",
    severity: "HIGH",
    description: "The Cisco MPLS router must be configured to have TTL Propagation disabled.  GROUP ID: V-216610  RULE ID: SV-216610r531085",
    rationale: "The head end of the label-switched path (LSP), the label edge router (LER) will  decrement the IP packet's time-to-live (TTL) value by one and then copy the value to  the MPLS TTL field. At each label-switched router (LSR) hop, the MPLS TTL value is  decremented by one. The MPLS router that pops the label (either the penultimate LSR  or the egress LER) will copy the packet's MPLS TTL value to the IP TTL field and  decrement it by one.  This TTL propagation is the default behavior. Because the MPLS TTL is propagated  from the IP TTL, a traceroute will list every hop in the path, be it routed or label  switched, thereby exposing core nodes. With TTL propagation disabled, LER  decrements the IP packet's TTL value by one and then places a value of 255 in the  packet's MPLS TTL field, which is then decremented by one as the packet passes  through each LSR in the MPLS core. Because the MPLS TTL never drops to zero, none  of the LSP hops triggers an ICMP TTL exceeded message and consequently, these  hops are not recorded in a traceroute. Hence, nodes within the MPLS core cannot be  discovered by an attacker.",
    audit: "Review the router configuration to verify that TTL propagation is disabled as shown in  the example below.  no mpls ip propagate-ttl  If the MPLS router is not configured to disable TTL propagation, this is a finding.",
    remediation: "Configure the MPLS router to disable TTL propagation as shown in the example below.  R5(config)#no mpls ip propagate-ttl     Internal Only - General",
    cci: "CCI-000366",
    expectedState: "Configure the MPLS router to disable TTL propagation as shown in the example below.",
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
