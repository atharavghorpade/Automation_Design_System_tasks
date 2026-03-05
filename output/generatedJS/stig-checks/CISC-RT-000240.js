var metadata = {
    groupIdNumber: "1.18",
    stigId: "CISC-RT-000240",
    ruleId: "RULE ID: SV-216572r531085",
    groupId: "GROUP ID: V-216572",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to deny network traffic by default and  allow network traffic by exception.  GROUP ID: V-216572  RULE ID: SV-216572r531085",
    rationale: "A deny-all, permit-by-exception network communications traffic policy ensures that only  connections that are essential and approved are allowed.  This requirement applies to both inbound and outbound network communications traffic.  All inbound and outbound traffic must be denied by default. Firewalls and perimeter  routers should only allow traffic through that is explicitly permitted. The initial defense for  the internal network is to block any traffic at the perimeter that is attempting to make a  connection to a host residing on the internal network. In addition, allowing unknown or  undesirable outbound traffic by the firewall or router will establish a state that will permit  the return of this undesirable traffic inbound.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify that the inbound ACL applied to all external  interfaces is configured to allow specific ports and protocols and deny all other traffic.  Step 1: Verify that an inbound ACL is applied to all external interfaces as shown in the  example below.  interface GigabitEthernet0/2  ip address x.11.1.2 255.255.255.254  ip access-group EXTERNAL_ACL in  Step 2: Review inbound ACL to verify that it is configured to deny all other traffic that is  not explicitly allowed.  ip access-list extended EXTERNAL_ACL  permit tcp any any established  permit tcp host x.11.1.1 eq bgp host x.11.1.2  permit tcp host x.11.1.1 host x.11.1.2 eq bgp  permit icmp host x.11.1.1 host x.11.1.2 echo  permit icmp host x.11.1.1 host x.11.1.2 echo-reply  …  …  …  deny ip any any log-input  If the ACL is not configured to allow specific ports and protocols and deny all other  traffic, this is a finding. If the ACL is not configured inbound on all external interfaces,  this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Step 1: Configure an inbound ACL to deny all other traffic by default as shown in the  example below.  R1(config)#ip access-list extended EXTERNAL_ACL  R1(config-ext-nacl)#permit tcp any any established  R1(config-ext-nacl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2    R1(config-ext-nacl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp  R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo  R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply  …  …  …  R1(config-ext-nacl)#deny ip any any log-input  Step 2: Apply the ingress filter to all external interfaces  R1(config)#int g0/2  R1(config-if)#ip access-group EXTERNAL_ACL in  Internal Only - General",
    cci: "CCI-001109",
    expectedState: "Step 1: Configure an inbound ACL to deny all other traffic by default as shown in the example below.",
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
