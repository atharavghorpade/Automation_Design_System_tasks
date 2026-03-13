var metadata = {
    groupIdNumber: "1.87",
    stigId: "CISC-RT-000900",
    ruleId: "SV-216633r856201",
    groupId: "V-216633",
    severity: "HIGH",
    description: "The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to  only accept MSDP packets from known MSDP peers.  GROUP ID: V-216633  RULE ID: SV-216633r856201",
    rationale: "MSDP peering with customer network routers presents additional risks to the DISN  Core, whether from a rogue or misconfigured MSDP-enabled router. To guard against  an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP- enabled RP routers must be configured to only accept MSDP packets from known  MSDP peers.",
    audit: "Review the router configuration to determine if there is a receive path or interface filter  to only accept MSDP packets from known MSDP peers.  Step 1: Verify that interfaces used for MSDP peering have an inbound ACL as shown in  the example.  interface GigabitEthernet1/1  ip address x.1.28.8 255.255.255.0  ip access-group EXTERNAL_ACL_INBOUND in  ip pim sparse-mode  Step 2: Verify that the ACL restricts MSDP peering to only known sources.  ip access-list extended EXTERNAL_ACL_INBOUND  permit tcp any any established  permit tcp host x.1.28.2 host x.1.28.8 eq 639  deny tcp any host x.1.28.8 eq 639 log  permit tcp host x.1.28.2 host 10.1.28.8 eq bgp  permit tcp host x.1.28.2 eq bgp host x.1.28.8  permit pim host x.1.28.2 pim host x.1.28.8  …  …  …  deny ip any any log  Note: MSDP connections is via TCP port 639  If the router is not configured to only accept MSDP packets from known MSDP peers,  this is a finding.  Internal Only - General",
    remediation: "Configure the receive path or interface ACLs to only accept MSDP packets from known  MSDP peers.  R8(config)#ip access-list extended EXTERNAL_ACL_INBOUND  R8(config-ext-nacl)#permit tcp any any established  R8(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq 639  R8(config-ext-nacl)#deny tcp any host x1.28.8 eq 639  R8(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq bgp  R8(config-ext-nacl)#permit tcp host x.1.28.2 eq bgp host x.1.28.8  R8(config-ext-nacl)#permit pim host x.1.28.2 host x.1.28.8  …  …  …  R8(config-ext-nacl)#deny ip any any",
    cci: "CCI-002403",
    expectedState: "Configure the receive path or interface ACLs to only accept MSDP packets from known MSDP peers.",
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

        if (line.indexOf("interface acls".toLowerCase()) !== -1) {

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
