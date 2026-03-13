var metadata = {
    groupIdNumber: "1.59",
    stigId: "CISC-RT-000560",
    ruleId: "SV-216604r856192",
    groupId: "V-216604",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to use the maximum prefixes feature to  protect against route table flooding and prefix de-aggregation attacks.  GROUP ID: V-216604  RULE ID: SV-216604r856192",
    rationale: "The effects of prefix de-aggregation can degrade router performance due to the size of  routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or  a misconfigured router, prefix de-aggregation occurs when the announcement of a large  prefix is fragmented into a collection of smaller prefix announcements.  In 1997, misconfigured routers in the Florida Internet Exchange network (AS7007) de- aggregated every prefix in their routing table and started advertising the first /24 block of  each of these prefixes as their own. Faced with this additional burden, the internal  routers became overloaded and crashed repeatedly. This caused prefixes advertised by  these routers to disappear from routing tables and reappear when the routers came  back online. As the routers came back after crashing, they were flooded with the routing  table information by their neighbors. The flood of information would again overwhelm  the routers and cause them to crash. This process of route flapping served to  destabilize not only the surrounding network but also the entire Internet. Routers trying  to reach those addresses would choose the smaller, more specific /24 blocks first. This  caused backbone networks throughout North America and Europe to crash.  Maximum prefix limits on peer connections combined with aggressive prefix-size  filtering of customers' reachability advertisements will effectively mitigate the de- aggregation risk. BGP maximum prefix must be used on all eBGP routers to limit the  number of prefixes that it should receive from a particular neighbor, whether customer  or peering AS. Consider each neighbor and how many routes they should be  advertising and set a threshold slightly higher than the number expected.  Internal Only - General",
    audit: "Review the router configuration to verify that the number of received prefixes from each  eBGP neighbor is controlled.  router bgp xx  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 maximum-prefix nnnnnnn  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 maximum-prefix nnnnnnn  If the router is not configured to control the number of prefixes received from each peer  to protect against route table flooding and prefix de-aggregation attacks, this is a  finding.",
    remediation: "Configure the router to use the maximum prefixes feature to protect against route table  flooding and prefix de-aggregation attacks as shown in the example below.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 maximum-prefix nnnnnnn  R1(config-router)#neighbor x.2.1.7 maximum-prefix nnnnnnn",
    cci: "CCI-002385",
    expectedState: "Configure the router to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks as shown in the example below.",
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
