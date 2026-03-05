var metadata = {
    groupIdNumber: "1.58",
    stigId: "CISC-RT-000570",
    ruleId: "RULE ID: SV-216605r856193",
    groupId: "GROUP ID: V-216605",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to limit the prefix size on any inbound route  advertisement to /24 or the least significant prefixes issued to the customer.  GROUP ID: V-216605  RULE ID: SV-216605r856193",
    rationale: "The effects of prefix de-aggregation can degrade router performance due to the size of  routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or  a misconfigured router, prefix de-aggregation occurs when the announcement of a large  prefix is fragmented into a collection of smaller prefix announcements.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to determine if it is compliant with this requirement.  Step 1: Verify that a route filter has been configured to reject prefixes longer than /24, or  the least significant prefixes issued to the customers as shown in the example below:  ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24  ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32  Step 2: Verify that prefix filtering has been applied to each eBGP peer as shown in the  example:  router bgp xx  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 prefix-list FILTER_PREFIX_LENGTH in  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 prefix-list FILTER_PREFIX_LENGTH in  If the router is not configured to limit the prefix size on any inbound route advertisement  to /24, or the least significant prefixes issued to the customer, this is a finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to limit the prefix size on any route advertisement to /24 or the least  significant prefixes issued to the customer.  Step 1: Configure a prefix list to reject any prefix that is longer than /24.  R1(config)#ip prefix-list FILTER_PREFIX_LENGTH permit 0.0.0.0/0 ge 8 le 24  R1(config)#ip prefix-list FILTER_PREFIX_LENGTH deny 0.0.0.0/0 le 32  Step 2: Apply the prefix list to all eBGP peers as shown in the example below.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 prefix-list FILTER_PREFIX_LENGTH in  R1(config-router)#neighbor x.2.1.7 prefix-list FILTER_PREFIX_LENGTH in",
    cci: "CCI-002385",
    expectedState: "Configure the router to limit the prefix size on any route advertisement to /24 or the least significant prefixes issued to the customer.",
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
