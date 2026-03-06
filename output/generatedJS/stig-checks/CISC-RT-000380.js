var metadata = {
    groupIdNumber: "1.32",
    stigId: "CISC-RT-000380",
    ruleId: "SV-216586r856191",
    groupId: "V-216586",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to have Proxy ARP disabled on all  external interfaces.  GROUP ID: V-216586  RULE ID: SV-216586r856191",
    rationale: "When Proxy ARP is enabled on a router, it allows that router to extend the network (at  Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts  from different LAN segments to look like they are on the same segment, proxy ARP is  only safe when used between trusted LAN segments. Attackers can leverage the  trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets.  Proxy ARP should always be disabled on router interfaces that do not require it, unless  the router is being used as a LAN bridge.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if IP Proxy ARP is disabled on all external  interfaces as shown in the example below.  interface GigabitEthernet0/1  description link to DISN  ip address x.1.12.2 255.255.255.252  no ip proxy-arp  Note: By default Proxy ARP is enabled on all interfaces; hence, if enabled, it will not be  shown in the configuration.  If IP Proxy ARP is enabled on any external interface, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Disable Proxy ARP on all external interfaces as shown in the example below.  R2(config)#int g0/1    R2(config-if)#no ip proxy-arp     Internal Only - General",
    cci: "CCI-002403",
    expectedState: "Disable Proxy ARP on all external interfaces as shown in the example below.",
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
