var metadata = {
    groupIdNumber: "1.21",
    stigId: "CISC-RT-000270",
    ruleId: "SV-216575r863237",
    groupId: "V-216575",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to block inbound packets with source  Bogon IP address prefixes.  GROUP ID: V-216575  RULE ID: SV-216575r863237",
    rationale: "Packets with Bogon IP source addresses should never be allowed to traverse the IP  core. Bogon IP networks are RFC1918 addresses or address blocks that have never  been assigned by the IANA or have been reserved.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify that an ingress Access Control List (ACL)  applied to all external interfaces is blocking packets with Bogon source addresses.  Step 1: Verify an ACL has been configured containing the current Bogon prefixes as  shown in the example below.  ip access-list extended FILTER_PERIMETER  deny ip 0.0.0.0 0.255.255.255 any log-input  deny ip 10.0.0.0 0.255.255.255 any log-input  deny ip 100.64.0.0 0.63.255.255 any log-input  deny ip 127.0.0.0 0.255.255.255 any log-input  deny ip 169.254.0.0 0.0.255.255 any log-input  deny ip 172.16.0.0 0.15.255.255 any log-input  deny ip 192.0.0.0 0.0.0.255 any log-input  deny ip 192.0.2.0 0.0.0.255 any log-input  deny ip 192.168.0.0 0.0.255.255 any log-input  deny ip 198.18.0.0 0.1.255.255 any log-input  deny ip 198.51.100.0 0.0.0.255 any log-input  deny ip 203.0.113.0 0.0.0.255 any log-input  deny ip 224.0.0.0 31.255.255.255 any log-input  deny ip 240.0.0.0 15.255.255.255 any log-input  permit tcp any any established  permit tcp host x.12.1.9 host x.12.1.10 eq bgp  permit tcp host x.12.1.9 eq bgp host x.12.1.10  permit icmp host x.12.1.9 host x.12.1.10 echo  permit icmp host x.12.1.9 host x.12.1.10 echo-reply  …  …  …  deny ip any any log-input  Step 2: Verify that the inbound ACL applied to all external interfaces will block all traffic  from Bogon source addresses.  interface GigabitEthernet0/1  description Link to DISN  ip address x.12.1.10 255.255.255.254  ip access-group FILTER_PERIMETER in  If the router is not configured to block inbound packets with source Bogon IP address  prefixes, this is a finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the perimeter to block inbound packets with Bogon source addresses.  Step 1: Configure an ACL containing the current Bogon prefixes as shown below.  R5(config)#ip access-list extended FILTER_PERIMETER  R5(config-ext-nacl)#deny ip 0.0.0.0 0.255.255.255 any log-input  R5(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any log-input  R5(config-ext-nacl)#deny ip 100.64.0.0 0.63.255.255 any log-input  R5(config-ext-nacl)#deny ip 127.0.0.0 0.255.255.255 any log-input  R5(config-ext-nacl)#deny ip 169.254.0.0 0.0.255.255 any log-input  R5(config-ext-nacl)#deny ip 172.16.0.0 0.15.255.255 any log-input  R5(config-ext-nacl)#deny ip 192.0.0.0 0.0.0.255 any log-input  R5(config-ext-nacl)#deny ip 192.0.2.0 0.0.0.255 any log-input  R5(config-ext-nacl)#deny ip 192.168.0.0 0.0.255.255 any log-input  R5(config-ext-nacl)#deny ip 198.18.0.0 0.1.255.255 any log-input  R5(config-ext-nacl)#deny ip 198.51.100.0 0.0.0.255 any log-input  R5(config-ext-nacl)#deny ip 203.0.113.0 0.0.0.255 any log-input  R5(config-ext-nacl)#deny ip 224.0.0.0 31.255.255.255 any log-input  R5(config-ext-nacl)#deny ip 240.0.0.0 15.255.255.255 any log-input  R5(config-ext-nacl)#permit tcp any any established  R5(config-ext-nacl)#permit tcp host x.12.1.9 host x.12.1.10 eq bgp  R5(config-ext-nacl)#permit tcp host x.12.1.9 eq bgp host x.12.1.10  R5(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo  R5(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo-reply  …  …  …  R5(config-ext-nacl)#deny ip any any log-input  R5(config-ext-nacl)#end  Step 2: Apply the ACL inbound on all external interfaces.  R2(config)#int g0/0  R1(config-if)#ip access-group FILTER_PERIMETER in  R1(config-if)#end",
    cci: "CCI-002403",
    expectedState: "Configure the perimeter to block inbound packets with Bogon source addresses.",
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
