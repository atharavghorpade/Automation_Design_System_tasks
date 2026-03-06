var metadata = {
    groupIdNumber: "1.11",
    stigId: "CISC-RT-000200",
    ruleId: "RULE ID: SV-216568r531085",
    groupId: "GROUP ID: V-216568",
    severity: "HIGH",
    description: "The Cisco router must be configured to log all packets that have been dropped at  interfaces via an ACL.  GROUP ID: V-216568  RULE ID: SV-216568r531085",
    rationale: "Auditing and logging are key components of any security architecture. It is essential for  security personnel to know what is being done or attempted to be done, and by whom,  to compile an accurate risk assessment. Auditing the actions on network devices  provides a means to recreate an attack or identify a configuration mistake on the device.",
    audit: "Review all Access Control Lists(ACLs) used to filter traffic and verify that packets being  dropped are logged as shown in the configuration below.  ip access-list extended INGRESS_FILTER  permit tcp any any established  permit tcp host x.11.1.1 eq bgp host x.11.1.2  permit tcp host x.11.1.1 host x.11.1.2 eq bgp  permit tcp any host x.11.1.5 eq www  permit icmp host x.11.1.1 host x.11.1.2 echo  permit icmp any any echo-reply  …  …  …  deny ip any any log  If packets being dropped at interfaces are not logged, this is a finding.",
    remediation: "Configure ACLs to log packets that are dropped as shown in the example below.  R5(config)#ip access-list extended INGRESS_FILTER  …  …  …  R5(config-ext-nacl)#deny ip any any log  Internal Only - General",
    cci: "CCI-000134",
    expectedState: "Configure ACLs to log packets that are dropped as shown in the example below.",
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
