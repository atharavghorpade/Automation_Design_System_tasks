var metadata = {
    groupIdNumber: "1.25",
    stigId: "CISC-RT-000310",
    ruleId: "RULE ID: SV-216989r531085",
    groupId: "GROUP ID: V-216989",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to restrict it from accepting outbound IP  packets that contain an illegitimate address in the source address field via egress filter  or by enabling Unicast Reverse Path Forwarding (uRPF).  GROUP ID: V-216989  RULE ID: SV-216989r531085",
    rationale: "A compromised host in an enclave can be used by a malicious platform to launch  cyberattacks on third parties. This is a common practice in \"botnets\", which are a  collection of compromised computers using malware to attack other computers or  networks. DDoS attacks frequently leverage IP source address spoofing to send  packets to multiple hosts that in turn will then send return traffic to the hosts with the IP  addresses that were forged. This can generate significant amounts of traffic. Therefore,  protection measures to counteract IP source address spoofing must be taken. When  uRPF is enabled in strict mode, the packet must be received on the interface that the  device would use to forward the return packet; thereby mitigating IP source address  spoofing.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify uRPF or an egress ACL has been configured  on all internal interfaces to restrict the router from accepting outbound IP packets that  contain an illegitimate address in the source address field.  uRPF example  interface GigabitEthernet0/1  description downstream link to LAN  ip address 10.1.25.5 255.255.255.0  ip verify unicast source reachable-via rx  Egress ACL example  interface GigabitEthernet0/1  description downstream link to LAN  ip address 10.1.25.5 255.255.255.0  ip access-group EGRESS_FILTER in  …  …  …  ip access-list extended EGRESS_FILTER  permit udp 10.1.15.0 0.0.0.255 any eq domain  permit tcp 10.1.15.0 0.0.0.255 any eq ftp  permit tcp 10.1.15.0 0.0.0.255 any eq ftp-data  permit tcp 10.1.15.0 0.0.0.255 any eq www  permit icmp 10.1.15.0 0.0.0.255 any  permit icmp 10.1.15.0 0.0.0.255 any echo  deny ip any any  If uRPF or an egress ACL to restrict the router from accepting outbound IP packets that  contain an illegitimate address in the source address field has not been configured on  all internal interfaces in an enclave, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to ensure that an egress ACL or uRPF is configured on internal  interfaces to restrict the router from accepting any outbound IP packet that contains an  illegitimate address in the source field. The example below enables uRPF.  R5(config)#int g0/1  R5(config-if)#ip verify unicast source reachable-via rx     Internal Only - General",
    cci: "CCI-001094",
    expectedState: "Configure the router to ensure that an egress ACL or uRPF is configured on internal interfaces to restrict the router from accepting any outbound IP packet that contains an illegitimate address in the source field.",
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

        if (line.indexOf("ip packet".toLowerCase()) !== -1) {

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
