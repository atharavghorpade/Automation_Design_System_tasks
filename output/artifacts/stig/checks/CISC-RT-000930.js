var metadata = {
    groupIdNumber: "1.90",
    stigId: "CISC-RT-000930",
    ruleId: "RULE ID: SV-216636r531085",
    groupId: "GROUP ID: V-216636",
    severity: "HIGH",
    description: "The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to  filter source-active multicast advertisements to external MSDP peers to avoid global  visibility of local-only multicast sources and groups.  GROUP ID: V-216636  RULE ID: SV-216636r531085",
    rationale: "To avoid global visibility of local information, there are a number of source-group (S, G)  states in a PIM-SM domain that must not be leaked to another domain, such as  multicast sources with private address, administratively scoped multicast addresses,  and the auto-RP groups (224.0.1.39 and 224.0.1.40).  Allowing a multicast distribution tree, local to the core, to extend beyond its boundary  could enable local multicast traffic to leak into other autonomous systems and customer  networks.",
    audit: "Review the router configuration to determine if there is export policy to block local  source-active multicast advertisements.  Step 1: Verify that an outbound source-active filter is bound to each MSDP peer as  shown in the example below.  ip msdp peer 10.1.28.8 remote-as 8  ip msdp sa-filter out 10.1.28.8 list OUTBOUND_MSDP_SA_FILTER  Step 2: Review the access lists referenced by the source-active filters and verify that  MSDP source-active messages being sent to MSDP peers do not leak advertisements  that are local.  ip access-list extended OUTBOUND_MSDP_SA_FILTER  deny ip 10.0.0.0 0.255.255.255 any  permit ip any any  If the router is not configured with an export policy to filter local source-active multicast  advertisements, this is a finding.  Internal Only - General",
    remediation: "Configure the router with an export policy avoid global visibility of local multicast (S, G)  states. The example below will prevent exporting multicast active sources belonging to  the private network.  R8(config)#ip access-list extended OUTBOUND_MSDP_SA_FILTER  R8(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any  R8(config-ext-nacl)#permit ip any any  R8(config-ext-nacl)#exit  R8(config)#ip msdp sa-filter in x.1.28.2 list OUTBOUND_MSDP_SA_FILTER",
    cci: "CCI-001368",
    expectedState: "Configure the router with an export policy avoid global visibility of local multicast (S, G) states.",
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
