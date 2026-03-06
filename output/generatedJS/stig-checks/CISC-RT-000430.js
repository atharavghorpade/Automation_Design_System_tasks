var metadata = {
    groupIdNumber: "1.45",
    stigId: "CISC-RT-000430",
    ruleId: "RULE ID: SV-216591r531085",
    groupId: "GROUP ID: V-216591",
    severity: "HIGH",
    description: "The Cisco out-of-band management (OOBM) gateway router must be configured to not  redistribute routes between the management network routing domain and the managed  network routing domain.  GROUP ID: V-216591  RULE ID: SV-216591r531085",
    rationale: "If the gateway router is not a dedicated device for the OOBM network, several  safeguards must be implemented for containment of management and production traffic  boundaries; otherwise, it is possible that management traffic will not be separated from  production traffic.  Since the managed network and the management network are separate routing  domains, separate Interior Gateway Protocol routing instances must be configured on  the router, one for the managed network and one for the OOBM network. In addition,  the routes from the two domains must not be redistributed to each other.  Internal Only - General",
    audit: "This requirement is not applicable for the DODIN Backbone.  Verify the Interior Gateway Protocol (IGP) instance used for the managed network does  not redistribute routes into the IGP instance used for the management network, and vice  versa. The example below imports OSPF routes from the production route table (VRF  PROD) into the management route table (VRF MGMT) using BGP.  ip vrf MGMT  rd 4:4  route-target export 4:4  route-target import 4:4  route-target import 8:8  !  ip vrf PROD  rd 8:8  route-target import 8:8  route-target export 8:8  …  …  …  router ospf 1 vrf MGMT  log-adjacency-changes  redistribute bgp 64512 subnets  network 0.0.0.0 255.255.255.255 area 0  !  router ospf 2 vrf PROD  log-adjacency-changes  network 0.0.0.0 255.255.255.255 area 0  !  router bgp 64512  no synchronization  bgp log-neighbor-changes  no auto-summary  !  address-family ipv4 vrf MGMT  no synchronization  redistribute ospf 1 vrf MGMT  exit-address-family  !  address-family ipv4 vrf PROD  no synchronization  redistribute ospf 2 vrf PROD  exit-address-family  If the IGP instance used for the managed network redistributes routes into the IGP  instance used for the management network, or vice versa, this is a finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Remove the configuration that imports routes from the managed network into the  management network or vice versa as shown in the example below.  R1(config)#ip vrf MGMT  R1(config-vrf)#no route-target import 8:8",
    cci: "CCI-001414",
    expectedState: "Remove the configuration that imports routes from the managed network into the management network or vice versa as shown in the example below.",
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
