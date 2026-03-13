var metadata = {
    groupIdNumber: "1.89",
    stigId: "CISC-RT-000920",
    ruleId: "SV-216635r531085",
    groupId: "V-216635",
    severity: "HIGH",
    description: "The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to  filter received source-active multicast advertisements for any undesirable multicast  groups and sources.  GROUP ID: V-216635  RULE ID: SV-216635r531085",
    rationale: "The interoperability of BGP extensions for interdomain multicast routing and MSDP  enables seamless connectivity of multicast domains between autonomous systems.  MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol  Independent Multicast (PIM) routers to perform RPF checks and build multicast  distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode  domains, allowing RPs from different domains to share information about active  sources. When RPs in peering multicast domains hear about active sources, they can  pass on that information to their local receivers, thereby allowing multicast data to be  forwarded between the domains. Configuring an import policy to block multicast  advertisements for reserved, Martian, single-source multicast, and any other  undesirable multicast groups, as well as any source-group (S, G) states with Bogon  source addresses, would assist in avoiding unwanted multicast traffic from traversing  the core.  Internal Only - General",
    audit: "Review the router configuration to determine if there is import policy to block source- active multicast advertisements for any undesirable multicast groups, as well as any (S,  G) states with undesirable source addresses.  Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.  ip msdp peer x.1.28.2 remote-as 2  ip msdp sa-filter in x.1.28.2 list INBOUND_MSDP_SA_FILTER  Step 2: Review the access lists referenced by the source-active filter to verify that  undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and  advertisements from undesirable sources are blocked.  ip access-list extended INBOUND_MSDP_SA_FILTER  deny ip any host 224.0.1.3  deny ip any host 224.0.1.24  deny ip any host 224.0.1.22  deny ip any host 224.0.1.2  deny ip any host 224.0.1.35  deny ip any host 224.0.1.60  deny ip any host 224.0.1.39  deny ip any host 224.0.1.40  deny ip any 232.0.0.0 0.255.255.255  deny ip any 239.0.0.0 0.255.255.255  deny ip 10.0.0.0 0.255.255.255 any  deny ip 127.0.0.0 0.255.255.255 any  deny ip 172.16.0.0 0.15.255.255 any  deny ip 192.168.0.0 0.0.255.255 any  permit ip any any  If the router is not configured with an import policy to filter undesirable SA multicast  advertisements, this is a finding.  Internal Only - General",
    remediation: "Configure the MSDP router to filter received source-active multicast advertisements for  any undesirable multicast groups and sources as shown in the example below.  R8(config)#ip access-list extended INBOUND_MSDP_SA_FILTER  R8(config-ext-nacl)#deny ip any host 224.0.1.3 ! Rwhod  R8(config-ext-nacl)#deny ip any host 224.0.1.24 ! Microsoft-ds  R8(config-ext-nacl)#deny ip any host 224.0.1.22 ! SVRLOC  R8(config-ext-nacl)#deny ip any host 224.0.1.2 ! SGI-Dogfight  R8(config-ext-nacl)#deny ip any host 224.0.1.35 ! SVRLOC-DA  R8(config-ext-nacl)#deny ip any host 224.0.1.60 ! hp-device-disc  R8(config-ext-nacl)#deny ip any host 224.0.1.39 ! Auto-RP  R8(config-ext-nacl)#deny ip any host 224.0.1.40 ! Auto-RP  R8(config-ext-nacl)#deny ip any 232.0.0.0 0.255.255.255 ! SSM range  R8(config-ext-nacl)#deny ip any 239.0.0.0 0.255.255.255 ! Admin scoped range  R8(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any ! RFC 1918 address range  R8(config-ext-nacl)#deny ip 127.0.0.0 0.255.255.255 any ! RFC 1918 address range  R8(config-ext-nacl)#deny ip 172.16.0.0 0.15.255.255 any ! RFC 1918 address range  R8(config-ext-nacl)#deny ip 192.168.0.0 0.0.255.255 any ! RFC 1918 address range  R8(config-ext-nacl)#permit ip any any  R8(config-ext-nacl)#exit  R8(config)#ip msdp sa-filter in x.1.28.2 list INBOUND_MSDP_SA_FILTER",
    cci: "CCI-001368",
    expectedState: "Configure the MSDP router to filter received source-active multicast advertisements for any undesirable multicast groups and sources as shown in the example below.",
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
