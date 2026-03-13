var metadata = {
    groupIdNumber: "1.15",
    stigId: "CISC-RT-000235",
    ruleId: "SV-229030r878127",
    groupId: "V-229030",
    severity: "HIGH",
    description: "The Cisco router must be configured to have Cisco Express Forwarding enabled.  GROUP ID: V-229030  RULE ID: SV-229030r878127",
    rationale: "The Cisco Express Forwarding (CEF) switching mode replaces the traditional Cisco  routing cache with a data structure that mirrors the entire system routing table. Because  there is no need to build cache entries when traffic starts arriving for new destinations,  CEF behaves more predictably when presented with large volumes of traffic addressed  to many destinations—such as a SYN flood attacks that. Because many SYN flood  attacks use randomized source addresses to which the hosts under attack will reply to,  there can be a substantial amount of traffic for a large number of destinations that the  router will have to handle. Consequently, routers configured for CEF will perform better  under SYN floods directed at hosts inside the network than routers using the traditional  cache.",
    audit: "Review the router to verify that CEF is enabled.  IPv4 Example: ip cef  IPv6 Example: ipv6 cef  If CEF is not enabled, this is a finding.",
    remediation: "Enable CEF  IPv4 Example: ip cef  IPv6 Example: ipv6 cef",
    cci: "CCI-000366",
    expectedState: "Enable CEF IPv4 Example: ip cef IPv6 Example: ipv6 cef",
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

        if (line.indexOf("ip cef".toLowerCase()) !== -1) {

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
