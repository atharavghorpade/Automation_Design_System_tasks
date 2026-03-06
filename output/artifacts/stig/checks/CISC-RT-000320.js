var metadata = {
    groupIdNumber: "1.26",
    stigId: "CISC-RT-000320",
    ruleId: "RULE ID: SV-216580r531085",
    groupId: "GROUP ID: V-216580",
    severity: "HIGH",
    description: "The Cisco perimeter router must be configured to filter traffic destined to the enclave in  accordance with the guidelines contained in DoD Instruction 8551.1.  GROUP ID: V-216580  RULE ID: SV-216580r531085",
    rationale: "Vulnerability assessments must be reviewed by the System Administrator, and  protocols must be approved by the Information Assurance (IA) staff before entering the  enclave.  Access control lists (ACLs) are the first line of defense in a layered security approach.  They permit authorized packets and deny unauthorized packets based on port or  service type. They enhance the posture of the network by not allowing packets to reach  a potential target within the security domain. The lists provided are highly susceptible  ports and services that should be blocked or limited as much as possible without  adversely affecting customer requirements. Auditing packets attempting to penetrate the  network but that are stopped by an ACL will allow network administrators to broaden  their protective ring and more tightly define the scope of operation.  If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is  in accordance with DoD Instruction 8551.1, and if the permit rule is explicitly defined  with explicit ports and protocols allowed, then all requirements related to PPS being  blocked would be satisfied.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify that the ingress ACL is in accordance with DoD  8551.1.  Step 1: Verify that an inbound ACL is configured on all external interfaces.  interface GigabitEthernet0/2  ip address x.11.1.2 255.255.255.254  ip access-group EXTERNAL_ACL_INBOUND in  Step 2. Review the inbound ACL to verify that it is filtering traffic in accordance with  DoD 8551.1.  ip access-list extended EXTERNAL_ACL_INBOUND  permit tcp any any established  permit tcp host x.11.1.1 eq bgp host x.11.1.2  permit tcp host x.11.1.1 host x.11.1.2 eq bgp  permit icmp host x.11.1.1 host x.11.1.2 echo  permit icmp host x.11.1.1 host x.11.1.2 echo-reply  …  … < must be in accordance with DoD Instruction 8551.1>  …  deny ip any any log-input  If the router does not filter traffic in accordance with the guidelines contained in DoD  8551.1, this is a finding.",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to use an inbound ACL on all external interfaces as shown in the  example below to restrict traffic in accordance with the guidelines contained in DOD  Instruction 8551.1.  R1(config)#ip access-list extended EXTERNAL_ACL_INBOUND  R1(config-ext-nacl)#permit tcp any any established  R1(config-ext-nacl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2    R1(config-ext-nacl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp  R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo  R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply  …  … < must be in accordance with DoD Instruction 8551.1>  …  R1(config-ext-nacl)#deny ip any any log-input  R1(config-ext-nacl)#exit  R1(config)#int g0/2  R1(config-if)#ip access-group EXTERNAL_ACL_INBOUND in  Internal Only - General",
    cci: "CCI-001097",
    expectedState: "Configure the router to use an inbound ACL on all external interfaces as shown in the example below to restrict traffic in accordance with the guidelines contained in DOD Instruction 8551.1.",
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
