var metadata = {
    groupIdNumber: "1.44",
    stigId: "CISC-RT-000420",
    ruleId: "RULE ID: SV-216590r531085",
    groupId: "GROUP ID: V-216590",
    severity: "HIGH",
    description: "The Cisco out-of-band management (OOBM) gateway router must be configured to  have separate IGP instances for the managed network and management network.  GROUP ID: V-216590  RULE ID: SV-216590r531085",
    rationale: "If the gateway router is not a dedicated device for the OOBM network, implementation  of several safeguards for containment of management and production traffic boundaries  must occur. Since the managed and management network are separate routing  domains, configuration of separate Interior Gateway Protocol routing instances is critical  on the router to segregate traffic from each network.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Verify that the OOBM interface is an adjacency in the IGP domain for the management  network via separate VRF as shown in the example below.  router ospf 1 vrf MGMT  log-adjacency-changes  network 0.0.0.0 255.255.255.255 area 0  !  router ospf 2 vrf PROD  log-adjacency-changes  network 0.0.0.0 255.255.255.255 area 0  If the router is not configured to have separate IGP instances for the managed network  and management network, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to have a separate IGP instance for the management network as  shown in the example below.  R3(config)#router ospf 1 vrf MGMT  R3(config-router)#network 0.0.0.0 0.0.0.0 area 0  R3(config-router)#exit  R3(config)#router ospf 2 vrf PROD  R3(config-router)#network 0.0.0.0 0.0.0.0 area 0  R3(config-router)#end  Internal Only - General",
    cci: "CCI-001414",
    expectedState: "Configure the router to have a separate IGP instance for the management network as shown in the example below.",
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
