var metadata = {
    groupIdNumber: "1.20",
    stigId: "CISC-RT-000260",
    ruleId: "RULE ID: SV-216574r856187",
    groupId: "GROUP ID: V-216574",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to only allow incoming communications  from authorized sources to be routed to authorized destinations.  GROUP ID: V-216574  RULE ID: SV-216574r856187",
    rationale: "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to  other connected networks. Additionally, unrestricted traffic may transit a network, which  uses bandwidth and other resources.  Traffic can be restricted directly by an access control list (ACL), which is a firewall  function, or by Policy Routing. Policy Routing is a technique used to make routing  decisions based on a number of different criteria other than just the destination network,  including source or destination network, source or destination address, source or  destination port, protocol, packet size, and packet classification. This overrides the  router's normal routing procedures used to control the specific paths of network traffic. It  is normally used for traffic engineering but can also be used to meet security  requirements; for example, traffic that is not allowed can be routed to the Null0 or  discard interface. Policy Routing can also be used to control which prefixes appear in  the routing table.  This requirement is intended to allow network administrators the flexibility to use  whatever technique is most effective.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if the router allows only incoming  communications from authorized sources to be routed to authorized destinations. The  hypothetical example below allows inbound NTP from server x.1.12.9 only to host  x.12.1.21.  ip access-list extended FILTER_PERIMETER  permit tcp any any established  …  …  …  permit udp host x.12.1.9 host x.12.1.21 eq ntp  deny ip any any log-input  If the router does not restrict incoming communications to allow only authorized sources  and destinations, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to allow only incoming communications from authorized sources to  be routed to authorized destinations.  R1(config)#ip access-list extended FILTER_PERIMETER  R1(config-ext-nacl)#nn permit udp host x.12.1.9 host x.12.1.21 eq ntp  R1(config-ext-nacl)#end",
    cci: "CCI-002403",
    expectedState: "Configure the router to allow only incoming communications from authorized sources to be routed to authorized destinations.",
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
