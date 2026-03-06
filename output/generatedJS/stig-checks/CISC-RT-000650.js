var metadata = {
    groupIdNumber: "1.67",
    stigId: "CISC-RT-000650",
    ruleId: "RULE ID: SV-216613r531085",
    groupId: "GROUP ID: V-216613",
    severity: "HIGH",
    description: "The Cisco PE router must be configured to have each VRF with the appropriate Route  Distinguisher (RD).  GROUP ID: V-216613  RULE ID: SV-216613r531085",
    rationale: "An RD provides uniqueness to the customer address spaces within the MPLS L3VPN  infrastructure. The concept of the VPN-IPv4 and VPN-IPv6 address families consists of  the RD prepended before the IP address. Hence, if the same IP prefix is used in several  different L3VPNs, it is possible for BGP to carry several completely different routes for  that prefix, one for each VPN.  Since VPN-IPv4 addresses and IPv4 addresses are different address families, BGP  never treats them as comparable addresses. The purpose of the RD is to create distinct  routes for common IPv4 address prefixes. On any given PE router, a single RD can  define a VRF in which the entire address space may be used independently, regardless  of the makeup of other VPN address spaces. Hence, it is imperative that a unique RD is  assigned to each L3VPN and that the proper RD is configured for each VRF.",
    audit: "Review the design plan for MPLS/L3VPN to determine what RD have been assigned for  each VRF. Review the router configuration and verify that the correct RD is configured  for each VRF. In the example below, route distinguisher 13:13 has been configured for  customer 1.  ip vrf CUST1  rd 13:13  Note: This requirement is only applicable for MPLS L3VPN implementations.  If the wrong RD has been configured for any VRF, this is a finding.",
    remediation: "Configure the correct RD for each VRF.  R5(config)#ip vrf CUST1  R5(config-vrf)#rd 13:13  R5(config-vrf)#end     Internal Only - General",
    cci: "CCI-000366",
    expectedState: "Configure the correct RD for each VRF.",
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
