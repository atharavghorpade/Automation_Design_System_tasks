var metadata = {
    groupIdNumber: "1.77",
    stigId: "CISC-RT-000800",
    ruleId: "RULE ID: SV-216623r531085",
    groupId: "GROUP ID: V-216623",
    severity: "HIGH",
    description: "The Cisco multicast router must be configured to bind a Protocol Independent Multicast  (PIM) neighbor filter to interfaces that have PIM enabled.  GROUP ID: V-216623  RULE ID: SV-216623r531085",
    rationale: "PIM is a routing protocol used to build multicast distribution trees for forwarding  multicast traffic across the network infrastructure. PIM traffic must be limited to only  known PIM neighbors by configuring and binding a PIM neighbor filter to those  interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those  interfaces that have PIM enabled, unauthorized routers can join the PIM domain,  discover and use the rendezvous points, and also advertise their rendezvous points into  the domain. This can result in a denial of service by traffic flooding or result in the  unauthorized transfer of data.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Step 1: Verify all interfaces enabled for PIM have a neighbor ACL bound to the interface  as shown in the example below.  interface GigabitEthernet1/1  ip address 10.1.2.2 255.255.255.0  ip pim neighbor-filter PIM_NEIGHBORS  ip pim sparse-mode  Step 2: Review the configured ACL for filtering PIM neighbors as shown in the example  below.  ip access-list standard PIM_NEIGHBORS  permit 10.1.2.6  If PIM neighbor ACLs are not bound to all interfaces that have PIM enabled, this is a  finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure neighbor ACLs to only accept PIM control plane traffic from documented PIM  neighbors. Bind neighbor ACLs to all PIM enabled interfaces.  Step 1: Configure ACL for PIM neighbors  R2(config)#ip access-list standard PIM_NEIGHBORS  R2(config-std-nacl)#permit 10.1.2.6  R2(config-std-nacl)#exit  Step 2: Apply the ACL to all interfaces enabled for PIM  R2(config)#int g1/1  R2(config-if)#ip pim neighbor-filter PIM_NEIGHBORS",
    cci: "CCI-001414",
    expectedState: "Configure neighbor ACLs to only accept PIM control plane traffic from documented PIM neighbors.",
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
