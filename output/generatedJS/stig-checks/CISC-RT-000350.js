var metadata = {
    groupIdNumber: "1.29",
    stigId: "CISC-RT-000350",
    ruleId: "RULE ID: SV-216990r856207",
    groupId: "GROUP ID: V-216990",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to block all packets with any IP options.  GROUP ID: V-216990  RULE ID: SV-216990r856207",
    rationale: "Packets with IP options are not fast switched and henceforth must be punted to the  router processor. Hackers who initiate denial-of-service (DoS) attacks on routers  commonly send large streams of packets with IP options. Dropping the packets with IP  options reduces the load of IP options packets on the router. The end result is a  reduction in the effects of the DoS attack on the router and on downstream routers.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if it will block all packets with IP options.  ip access-list extended EXTERNAL_ACL  permit tcp any any established  deny ip any any option any-options  permit …  …  …    …  deny ip any any log-input  If the router is not configured to drop all packets with IP options, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to drop all packets with IP options.  R1(config)#ip access-list extended EXTERNAL_ACL  R1(config-ext-nacl)#15 deny ip any any option any-options",
    cci: "CCI-002403",
    expectedState: "Configure the router to drop all packets with IP options.",
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

        if (line.indexOf("ip options.".toLowerCase()) !== -1) {

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
