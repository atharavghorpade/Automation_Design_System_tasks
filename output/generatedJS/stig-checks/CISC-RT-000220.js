var metadata = {
    groupIdNumber: "1.13",
    stigId: "CISC-RT-000220",
    ruleId: "RULE ID: SV-216570r531085",
    groupId: "GROUP ID: V-216570",
    severity: "HIGH",
    description: "The Cisco router must be configured to produce audit records containing information to  establish the source of the events.  GROUP ID: V-216570  RULE ID: SV-216570r531085",
    rationale: "Without establishing the source of the event, it is impossible to establish, correlate, and  investigate the events leading up to an outage or attack.  In order to compile an accurate risk assessment and provide forensic analysis, security  personnel need to know the source of the event.  In addition to logging where events occur within the network, the audit records must  also identify sources of events such as IP addresses, processes, and node or device  names.",
    audit: "Review the router configuration to verify that events are logged containing information to  establish the source of the events as shown in the example below.  ip access-list extended INGRESS_FILTER  permit tcp any any established  permit tcp host x.11.1.1 eq bgp host x.11.1.2  permit tcp host x.11.1.1 host x.11.1.2 eq bgp  permit tcp any host x.11.1.5 eq www  permit icmp host x.11.1.1 host x.11.1.2 echo  permit icmp any any echo-reply  …  …  …  deny ip any any log-input  Note: When the log-input parameter is configured on deny statements, the log record  will contain the layer 2 address of the forwarding device for any packet being dropped.  If the router is not configured to produce audit records containing information to  establish the source of the events, this is a finding.  Internal Only - General",
    remediation: "Configure the router to log events containing information to establish where the events  occurred as shown in the example below.  R5(config)#ip access-list extended INGRESS_FILTER  …  …  …  R5(config-ext-nacl)#deny ip any any log-input",
    cci: "CCI-000133",
    expectedState: "Configure the router to log events containing information to establish where the events occurred as shown in the example below.",
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
