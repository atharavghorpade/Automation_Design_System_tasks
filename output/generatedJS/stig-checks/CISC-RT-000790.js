var metadata = {
    groupIdNumber: "1.76",
    stigId: "CISC-RT-000790",
    ruleId: "RULE ID: SV-216622r531085",
    groupId: "GROUP ID: V-216622",
    severity: "HIGH",
    description: "The Cisco multicast router must be configured to disable Protocol Independent Multicast  (PIM) on all interfaces that are not required to support multicast routing.  GROUP ID: V-216622  RULE ID: SV-216622r531085",
    rationale: "If multicast traffic is forwarded beyond the intended boundary, it is possible that it can  be intercepted by unauthorized or unintended personnel. Limiting where, within the  network, a given multicast group's data is permitted to flow is an important first step in  improving multicast security.  A scope zone is an instance of a connected region of a given scope. Zones of the same  scope cannot overlap while zones of a smaller scope will fit completely within a zone of  a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the  administratively configured boundary fits within the bounds of a site. According to RFC  4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to  be \"convex from a routing perspective\"; that is, packets routed within a zone must not  pass through any links that are outside of the zone. This requirement forces each zone  to be one contiguous island rather than a series of separate islands.  As stated in the DoD IPv6 IA Guidance for MO3, \"One should be able to identify all  interfaces of a zone by drawing a closed loop on their network diagram, engulfing some  routers and passing through some routers to include only some of their interfaces.\"  Therefore, it is imperative that the network engineers have documented their multicast  topology and thereby knows which interfaces are enabled for multicast. Once this is  done, the zones can be scoped as required.",
    audit: "Step 1: Review the network's multicast topology diagram.  Step 2: Review the router configuration to verify that only the PIM interfaces as shown  in the multicast topology diagram are enabled for PIM as shown in the example below.  interface GigabitEthernet1/1  ip address 10.1.3.3 255.255.255.0  ip pim sparse-mode  If an interface is not required to support multicast routing and it is enabled, this is a  finding.  Internal Only - General",
    remediation: "Document all enabled interfaces for PIM in the network's multicast topology diagram.  Disable support for PIM on interfaces that are not required to support it.  R5(config)#int g1/1  R5(config-if)#no ip pim sparse-mode",
    cci: "CCI-001414",
    expectedState: "Disable support for PIM on interfaces that are not required to support it.",
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
