var metadata = {
    groupIdNumber: "1.19",
    stigId: "CISC-RT-000250",
    ruleId: "RULE ID: SV-216573r531085",
    groupId: "GROUP ID: V-216573",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to enforce approved authorizations for  controlling the flow of information between interconnected networks in accordance with  applicable policy.  GROUP ID: V-216573  RULE ID: SV-216573r531085",
    rationale: "Information flow control regulates authorized information to travel within a network and  between interconnected networks. Controlling the flow of network traffic is critical so it  does not introduce any unacceptable risk to the network infrastructure or data. An  example of a flow control restriction is blocking outside traffic claiming to be from within  the organization. For most routers, internal information flow control is a product of  system design.",
    audit: "Review the router configuration to verify that ACLs are configured to allow or deny traffic  for specific source and destination addresses as well as ports and protocols. In the  example below, the router is peering BGP with DISN. ICMP echo and echo-reply  packets are allowed for troubleshooting connectivity. WWW traffic is permitted inbound  to the NIPRNet host-facing web server (x.12.1.22).  interface GigabitEthernet0/1  description Link to DISN  ip address x.12.1.10 255.255.255.0  ip access-group FILTER_PERIMETER in  …  …  …  ip access-list extended FILTER_PERIMETER  permit tcp any any established  permit tcp host x.12.1.9 host x.12.1.10 eq bgp  permit tcp host x.12.1.9 eq bgp host x.12.1.10  permit icmp host x.12.1.9 host x.12.1.10 echo  permit icmp host x.12.1.9 host x.12.1.10 echo-reply  permit tcp any host x.12.1.22 eq www  deny ip any any log-input  If the router is not configured to enforce approved authorizations for controlling the flow  of information between interconnected networks, this is a finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Step 1: Configure an ACL to allow or deny traffic as shown in the example below.  R1(config)#ip access-list extended FILTER_PERIMETER  R1(config-ext-nacl)#permit tcp any any established  R1(config-ext-nacl)#permit tcp host x.12.1.9 host x.12.1.10 eq bgp  R1(config-ext-nacl)#permit tcp host x.12.1.9 eq bgp host x.12.1.10  R1(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo  R1(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo-reply  R1(config-ext-nacl)#permit tcp any host x.12.1.22 eq www  R1(config-ext-nacl)#deny ip any any log-input  R1(config-ext-nacl)#exit  Step 2: Apply the ACL inbound on all external interfaces.  R2(config)#int g0/0  R1(config-if)#ip access-group FILTER_PERIMETER in",
    cci: "CCI-001414",
    expectedState: "Step 1: Configure an ACL to allow or deny traffic as shown in the example below.",
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
