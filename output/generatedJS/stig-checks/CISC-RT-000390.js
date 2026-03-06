var metadata = {
    groupIdNumber: "1.33",
    stigId: "CISC-RT-000390",
    ruleId: "RULE ID: SV-216587r531085",
    groupId: "GROUP ID: V-216587",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to block all outbound management  traffic.  GROUP ID: V-216587  RULE ID: SV-216587r531085",
    rationale: "For in-band management, the management network must have its own subnet in order  to enforce control and access boundaries provided by Layer 3 network nodes, such as  routers and firewalls. Management traffic between the managed network elements and  the management network is routed via the same links and nodes as that used for  production or operational traffic. Safeguards must be implemented to ensure that the  management traffic does not leak past the perimeter of the managed network.",
    audit: "This requirement is not applicable for the DODIN Backbone.  The perimeter router of the managed network must be configured with an outbound  ACL on the egress interface to block all management traffic as shown in the example  below.  Step 1: Verify that all external interfaces have been configured with an outbound ACL  as shown in the example below.  interface GigabitEthernet0/2  description link to DISN  ip address x.11.1.2 255.255.255.254  ip access-group EXTERNAL_ACL_OUTBOUND out  Step 2: Verify that the outbound ACL discards management traffic as shown in the  example below.  ip access-list extended EXTERNAL_ACL_OUTBOUND  deny tcp any any eq tacacs log-input  deny tcp any any eq 22 log-input  deny udp any any eq snmp log-input  deny udp any any eq snmptrap log-input  deny udp any any eq syslog log-input  permit tcp any any eq www log-input  deny ip any any log-input  If management traffic is not blocked at the perimeter, this is a finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the perimeter router of the managed network with an outbound ACL on the  egress interface to block all management traffic.  Step 1: Configure an ACL to block egress management traffic.  R5(config)#ip access-list extended EXTERNAL_ACL_OUTBOUND  R5(config-ext-nacl)#deny tcp any any eq tacacs log-input  R5(config-ext-nacl)#deny tcp any any eq 22 log-input  R5(config-ext-nacl)#deny udp any any eq snmp log-input  R5(config-ext-nacl)#deny udp any any eq snmptrap log-input  R5(config-ext-nacl)#deny udp any any eq syslog log-input  R5(config-ext-nacl)#permit tcp any any eq www  R5(config-ext-nacl)#deny ip any any log-input  R5(config-ext-nacl)#exit  Note: Permit commands would be configured to allow applicable outbound traffic. The  example above is allowing web traffic.  Step 2: Configure the external interfaces with the outbound ACL.  R1(config)#int g0/2  R1(config-if)#ip access-group EXTERNAL_ACL_OUTBOUND out",
    cci: "CCI-001097",
    expectedState: "Configure the perimeter router of the managed network with an outbound ACL on the egress interface to block all management traffic.",
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

        if (line.indexOf("interface to".toLowerCase()) !== -1) {

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
