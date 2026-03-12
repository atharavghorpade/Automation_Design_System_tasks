var metadata = {
    groupIdNumber: "1.57",
    stigId: "CISC-RT-000550",
    ruleId: "SV-216603r531085",
    groupId: "V-216603",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to reject route advertisements from CE  routers with an originating AS in the AS_PATH attribute that does not belong to that  customer.  GROUP ID: V-216603  RULE ID: SV-216603r531085",
    rationale: "Verifying the path a route has traversed will ensure that the local AS is not used as a  transit network for unauthorized traffic. To ensure that the local AS does not carry any  prefixes that do not belong to any customers, all PE routers must be configured to reject  routes with an originating AS other than that belonging to the customer.",
    audit: "This requirement is not applicable for the DODIN Backbone.  Review the router configuration to verify the router is configured to deny updates  received from CE routers with an originating AS in the AS_PATH attribute that does not  belong to that customer.  Step 1: Review router configuration and verify that there is an as-path access-list  statement defined to only accept routes from a CE router whose AS did not originate the  route. The configuration should look similar to the following:  ip as-path access-list 10 permit ^yy$  ip as-path access-list 10 deny .*  Note: the characters “^” and “$” representing the beginning and the end of the  expression respectively are optional and are implicitly defined if omitted.  Step 2: Verify that the as-path access-list is referenced by the filter-list inbound for the  appropriate BGP neighbors as shown in the example below:  router bgp xx  neighbor x.1.4.12 remote-as yy  neighbor x.1.4.12 filter-list 10 in  If the router is not configured to reject updates from CE routers with an originating AS in  the AS_PATH attribute that does not belong to that customer, this is a finding.  Internal Only - General",
    remediation: "This requirement is not applicable for the DODIN Backbone.  Configure the router to reject updates from CE routers with an originating AS in the  AS_PATH attribute that does not belong to that customer.  Step 1: Configure the as-path ACL as shown in the example below:  R1(config)#ip as-path access-list 10 permit ^yy$  R1(config)#ip as-path access-list 10 deny .*  Step 2: Apply the as-path filter inbound as shown in the example below:  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.4.12 filter-list 10 in",
    cci: "CCI-000032",
    expectedState: "Configure the router to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.",
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
