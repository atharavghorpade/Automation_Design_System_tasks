var metadata = {
    groupIdNumber: "1.80",
    stigId: "CISC-RT-000830",
    ruleId: "RULE ID: SV-216626r531085",
    groupId: "GROUP ID: V-216626",
    severity: "HIGH",
    description: "The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol  Independent Multicast (PIM) Register messages received from the Designated Router  (DR) for any undesirable multicast groups and sources.  GROUP ID: V-216626  RULE ID: SV-216626r531085",
    rationale: "Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a  network segment with multicast packets, over-using the available bandwidth and  thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register  messages are accepted only for authorized multicast groups and sources.",
    audit: "Verify that the RP router is configured to filter PIM register messages. The example  below will deny any multicast streams for groups 239.5.0.0/16 and allow from only  sources 10.1.2.6 and 10.1.2.7.  ip pim rp-address 10.1.12.3  ip pim accept-register list PIM_REGISTER_FILTER  …  …  …  ip access-list extended PIM_REGISTER_FILTER  deny ip any 239.5.0.0 0.0.255.255  permit ip host 10.1.2.6 any  permit ip host 10.1.2.7 any  deny ip any any  If the RP router peering with PIM-SM routers is not configured with a policy to block  registration messages for any undesirable multicast groups and sources, this is a  finding.  Internal Only - General",
    remediation: "Configure the router to filter PIM register messages received from a multicast DR for  any undesirable multicast groups and sources. The example below will deny any  multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and  10.1.2.7.  R2(config)#ip access-list extended PIM_REGISTER_FILTER  R2(config-ext-nacl)#deny ip any 239.5.0.0 0.0.255.255  R2(config-ext-nacl)#permit ip host 10.1.2.6 any  R2(config-ext-nacl)#permit ip host 10.1.2.7 any  R2(config-ext-nacl)#deny ip any any  R2(config-ext-nacl)#exit  R2(config)#ip pim accept-register list PIM_REGISTER_FILTER  R2(config)#end",
    cci: "CCI-001414",
    expectedState: "Configure the router to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources.",
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
