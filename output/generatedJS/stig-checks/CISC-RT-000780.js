var metadata = {
    groupIdNumber: "1.75",
    stigId: "CISC-RT-000780",
    ruleId: "RULE ID: SV-216621r531085",
    groupId: "GROUP ID: V-216621",
    severity: "HIGH",
    description: "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to  limit the effects of packet flooding denial-of-service (DoS) attacks.  GROUP ID: V-216621  RULE ID: SV-216621r531085",
    rationale: "DoS is a condition when a resource is not available for legitimate users. Packet flooding  distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and  have the objective of overloading a network or circuit to deny or seriously degrade  performance, which denies access to the services that normally traverse the network or  circuit. Volumetric attacks have become relatively easy to launch using readily available  tools such as Low Orbit Ion Cannon or botnets.  Measures to mitigate the effects of a successful volumetric attack must be taken to  ensure that sufficient capacity is available for mission-critical traffic. Managing capacity  may include, for example, establishing selected network usage priorities or quotas and  enforcing them using rate limiting, Quality of Service (QoS), or other resource  reservation control methods. These measures may also mitigate the effects of sudden  decreases in network capacity that are the result of accidental or intentional physical  damage to telecommunications facilities (such as cable cuts or weather-related  outages).  Internal Only - General",
    audit: "Review the router configuration to determine if it is configured to enforce a QoS policy to  limit the effects of packet flooding DoS attacks.  Step 1: Verify that a class map has been configured for the Scavenger class as shown  in the example below.  class-map match-all SCAVENGER  match ip dscp cs1  Step 2: Verify that the policy map includes the SCAVENGER class with low priority as  shown in the following example below.  policy-map QOS_POLICY  class CONTROL_PLANE  priority percent 10  class C2_VOICE  priority percent 10  class VOICE  priority percent 15  class VIDEO  bandwidth percent 25  class PREFERRED_DATA  bandwidth percent 25  class SCAVENGER  bandwidth percent 5  class class-default  bandwidth percent 10  Note: Traffic out of profile must be marked at the customer access layer or CE egress  edge.  If the router is not configured to enforce a QoS policy to limit the effects of packet  flooding DoS attacks, this is a finding.",
    remediation: "Step 1: Configure a class map for the SCAVENGER class.  R5(config)#class-map match-all SCAVENGER  R5(config-cmap)#match ip dscp cs1  Step 2: Add the SCAVENGER class to the policy map as shown in the example below.  R5(config)#policy-map QOS_POLICY  R5(config-pmap-c)#no class class-default  R5(config-pmap)#class SCAVENGER  R5(config-pmap-c)#bandwidth percent 5  R5(config-pmap-c)#class class-default  R5(config-pmap-c)#bandwidth percent 10  R5(config-pmap-c)#end     Internal Only - General",
    cci: "CCI-001095",
    expectedState: "Step 1: Configure a class map for the SCAVENGER class.",
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
