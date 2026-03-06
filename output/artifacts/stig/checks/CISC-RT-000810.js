var metadata = {
    groupIdNumber: "1.78",
    stigId: "CISC-RT-000810",
    ruleId: "RULE ID: SV-216624r531085",
    groupId: "GROUP ID: V-216624",
    severity: "HIGH",
    description: "The Cisco multicast edge router must be configured to establish boundaries for  administratively scoped multicast traffic.  GROUP ID: V-216624  RULE ID: SV-216624r531085",
    rationale: "If multicast traffic is forwarded beyond the intended boundary, it is possible that it can  be intercepted by unauthorized or unintended personnel.  Administrative scoped multicast addresses are locally assigned and are to be used  exclusively by the enterprise network or enclave. Administrative scoped multicast traffic  must not cross the enclave perimeter in either direction. Restricting multicast traffic  makes it more difficult for a malicious user to access sensitive traffic.  Admin-Local scope is encouraged for any multicast traffic within a network intended for  network management, as well as for control plane traffic that must reach beyond link- local destinations.",
    audit: "Review the router configuration and verify that admin-scope multicast traffic is blocked  at the external edge as shown in the example below.  interface GigabitEthernet1/2  ip address x.1.12.2 255.255.255.252  ip pim sparse-mode  ip multicast boundary MULTICAST_SCOPE  …  …  …  ip access-list standard MULTICAST_SCOPE  deny 239.0.0.0 0.255.255.255  permit any  If the router is not configured to establish boundaries for administratively scoped  multicast traffic, this is a finding.  Internal Only - General",
    remediation: "Step 1: Configure the ACL to deny packets with multicast administratively scoped  destination addresses as shown in the example below.  R2(config)#ip access-list standard MULTICAST_SCOPE  R2(config-std-nacl)#deny 239.0.0.0 0.255.255.255  R2(config-std-nacl)#permit any  R2(config-std-nacl)#exit  Step 2: Apply the multicast boundary at the appropriate interfaces as shown in the  example below.  R2(config)#int g1/2  R2(config-if)#ip multicast boundary MULTICAST_SCOPE  R2(config-if)#end",
    cci: "CCI-001414",
    expectedState: "Step 1: Configure the ACL to deny packets with multicast administratively scoped destination addresses as shown in the example below.",
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
