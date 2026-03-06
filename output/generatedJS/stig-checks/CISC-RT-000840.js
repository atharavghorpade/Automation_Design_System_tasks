var metadata = {
    groupIdNumber: "1.81",
    stigId: "CISC-RT-000840",
    ruleId: "SV-216627r531085",
    groupId: "V-216627",
    severity: "HIGH",
    description: "The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol  Independent Multicast (PIM) Join messages received from the Designated Router (DR)  for any undesirable multicast groups.  GROUP ID: V-216627  RULE ID: SV-216627r531085",
    rationale: "Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a  network segment with multicast packets, over-using the available bandwidth and  thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join  messages are only accepted for authorized multicast groups.",
    audit: "Verify that the RP router is configured to filter PIM join messages for any undesirable  multicast groups. In the example below, groups from 239.8.0.0/16 are not allowed.  ip pim rp-address 10.2.2.2  ip pim accept-rp 10.2.2.2 FILTER_PIM_JOINS  …  …  …  ip access-list standard FILTER_PIM_JOINS  deny 239.8.0.0 0.0.255.255  permit any  !  If the RP is not configured to filter join messages received from the DR for any  undesirable multicast groups, this is a finding.",
    remediation: "Configure the RP to filter PIM join messages for any undesirable multicast groups as  shown in the example below.  R2(config)#ip access-list standard PIM_JOIN_FILTER  R2(config-std-nacl)#deny 239.8.0.0 0.0.255.255  R2(config-std-nacl)#permit any  R2(config-std-nacl)#exit  R2(config)#ip pim accept-rp 10.2.2.2 PIM_JOIN_FILTER  R2(config)#end  Internal Only - General",
    cci: "CCI-001414",
    expectedState: "Configure the RP to filter PIM join messages for any undesirable multicast groups as shown in the example below.",
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
