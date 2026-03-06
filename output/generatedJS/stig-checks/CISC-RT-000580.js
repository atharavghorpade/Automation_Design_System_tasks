var metadata = {
    groupIdNumber: "1.60",
    stigId: "CISC-RT-000580",
    ruleId: "RULE ID: SV-216606r531085",
    groupId: "GROUP ID: V-216606",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to use its loopback address as the source  address for iBGP peering sessions.  GROUP ID: V-216606  RULE ID: SV-216606r531085",
    rationale: "Using a loopback address as the source address offers a multitude of uses for security,  access, management, and scalability of the BGP routers. It is easier to construct  appropriate ingress filters for router management plane traffic destined to the network  management subnet since the source addresses will be from the range used for  loopback interfaces instead of a larger range of addresses used for physical interfaces.  Log information recorded by authentication and syslog servers will record the router’s  loopback address instead of the numerous physical interface addresses.  When the loopback address is used as the source for eBGP peering, the BGP session  will be harder to hijack since the source address to be used is not known globally,  making it more difficult for a hacker to spoof an eBGP neighbor. By using traceroute, a  hacker can easily determine the addresses for an eBGP speaker when the IP address  of an external interface is used as the source address. The routers within the iBGP  domain should also use loopback addresses as the source address when establishing  BGP sessions.  Internal Only - General",
    audit: "Step 1: Review the router configuration to verify that a loopback address has been  configured.  interface Loopback0  ip address 10.1.1.1 255.255.255.255  Step 2: Verify that the loopback interface is used as the source address for all iBGP  sessions.  router bgp xx  no synchronization  no bgp enforce-first-as  bgp log-neighbor-changes  redistribute static  neighbor 10.1.1.1 remote-as xx  neighbor 10.1.1.1 password xxxxxxxx  neighbor 10.1.1.1 update-source Loopback0  If the router does not use its loopback address as the source address for all iBGP  sessions, this is a finding.",
    remediation: "Configure the router to use its loopback address as the source address for all iBGP  peering.  R1(config)#router bgp xx  R1(config-router)#neighbor 10.1.1.1 update-source Loopback0",
    cci: "CCI-000366",
    expectedState: "Configure the router to use its loopback address as the source address for all iBGP peering.",
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
