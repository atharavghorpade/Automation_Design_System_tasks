var metadata = {
    groupIdNumber: "1.74",
    stigId: "CISC-RT-000770",
    ruleId: "RULE ID: SV-216620r917420",
    groupId: "GROUP ID: V-216620",
    severity: "HIGH",
    description: "The Cisco P router must be configured to enforce a Quality-of-Service (QoS) policy to  provide preferred treatment for mission-critical applications.  GROUP ID: V-216620  RULE ID: SV-216620r917420",
    rationale: "Different applications have unique requirements and toleration levels for delay, jitter,  bandwidth, packet loss, and availability. To manage the multitude of applications and  services, a network requires a QoS framework to differentiate traffic and provide a  method to manage network congestion. The Differentiated Services Model (DiffServ) is  based on per-hop behavior by categorizing traffic into different classes and enabling  each node to enforce a forwarding treatment to each packet as dictated by a policy.  Packet markings such as IP Precedence and its successor, Differentiated Services  Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic  types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic,  prioritizes it according to its relative importance, and provides priority treatment based  on the classification. It is imperative that end-to-end QoS is implemented within the IP  core network to provide preferred treatment for mission-critical applications.  Internal Only - General",
    audit: "Review the router configuration and verify that a QoS policy has been configured to  provide preferred treatment for mission-critical applications.  Step 1: Verify that the class-maps are configured to match on DSCP values as shown in  the configuration example below.  class-map match-all PREFERRED_DATA  match ip dscp af33  class-map match-all CONTROL_PLANE  match ip dscp cs6  class-map match-all VIDEO  match ip dscp af41  class-map match-all VOICE  match ip dscp ef  class-map match-all C2_VOICE  match ip dscp 47  Step 2: Verify that the policy map reserves the bandwidth for each traffic type as shown  in the following example:  policy-map QOS_POLICY  class CONTROL_PLANE  priority percent 10  class C2_VOICE  priority percent 10  class VOICE  priority percent 15  class VIDEO  bandwidth percent 25  class PREFERRED_DATA  bandwidth percent 25  class class-default  bandwidth percent 15  Step 3: Verify that an output service policy is bound to all interfaces as shown in the  configuration example below.  interface GigabitEthernet1/1  ip address 10.1.15.5 255.255.255.252  service-policy output QOS_POLICY  !  interface GigabitEthernet1/2  ip address 10.1.15.8 255.255.255.252  service-policy output QOS_POLICY  If the router is not configured to implement a QoS policy in accordance with the QoS  DODIN Technical Profile, this is a finding.  Internal Only - General",
    remediation: "Configure to enforce a QoS policy to provide preferred treatment for mission-critical  applications.  Step 1: Configure class-maps to match on DSCP values as shown in the configuration  example below.  R5(config)#class-map match-all PREFERRED_DATA  R5(config-cmap)#match ip dscp af33  R5(config-cmap)#class-map match-all CONTROL_PLANE  R5(config-cmap)#match ip dscp cs6  R5(config-cmap)#class-map match-all VIDEO  R5(config-cmap)#match ip dscp af41  R5(config-cmap)#class-map match-all VOICE  R5(config-cmap)#match ip dscp ef  R5(config-cmap)#class-map match-all C2_VOICE  R5(config-cmap)#match ip dscp 47  R5(config-cmap)#exit  Step 2: Configure a policy map to be applied to the core-layer-facing interface that  reserves the bandwidth for each traffic type as shown in the example below.  R5(config)#policy-map QOS_POLICY  R5(config-pmap)#class CONTROL_PLANE  R5(config-pmap-c)#priority percent 10  R5(config-pmap-c)#class C2_VOICE  R5(config-pmap-c)#priority percent 10  R5(config-pmap-c)#class VOICE  R5(config-pmap-c)#priority percent 15  R5(config-pmap-c)#class VIDEO  R5(config-pmap-c)#bandwidth percent 25  R5(config-pmap-c)#class PREFERRED_DATA  R5(config-pmap-c)#bandwidth percent 25  R5(config-pmap-c)#class class-default  R5(config-pmap-c)#bandwidth percent 15  R5(config-pmap-c)#exit  R5(config-pmap)#exit  Step 3: Apply the output service policy to all interfaces as shown in the configuration  example below.  R5(config)#int g1/1  R5(config-if)#service-policy output QOS_POLICY  R5(config-if)#exit  R5(config)#int g1/2  R5(config-if)#service-policy output QOS_POLICY  R5(config-if)#end     Internal Only - General",
    cci: "CCI-001095",
    expectedState: "Configure to enforce a QoS policy to provide preferred treatment for mission-critical applications.",
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
