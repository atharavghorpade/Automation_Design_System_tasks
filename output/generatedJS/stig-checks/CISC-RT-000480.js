var metadata = {
    groupIdNumber: "1.50",
    stigId: "CISC-RT-000480",
    ruleId: "SV-216992r877980",
    groupId: "V-216992",
    severity: "HIGH",
    description: "The Cisco BGP router must be configured to use a unique key for each autonomous  system (AS) that it peers with.  GROUP ID: V-216992  RULE ID: SV-216992r877980",
    rationale: "If the same keys are used between eBGP neighbors, the chance of a hacker  compromising any of the BGP sessions increases. It is possible that a malicious user  exists in one autonomous system who would know the key used for the eBGP session.  This user would then be able to hijack BGP sessions with other trusted neighbors.",
    audit: "This check is Not Applicable for JRSS internal EBGP use.  Review the BGP configuration to determine if it is peering with multiple autonomous  systems. Interview the ISSM and router administrator to determine if unique keys are  being used.  router bgp xx  no synchronization  bgp log-neighbor-changes  neighbor x.1.1.9 remote-as yy  neighbor x.1.1.9 password yyyyyyyy  neighbor x.2.1.7 remote-as zz  neighbor x.2.1.7 password zzzzzzzzz  If unique keys are not being used, this is a finding.",
    remediation: "Configure the router to use unique keys for each AS that it peers with as shown in the  example below.  R1(config)#router bgp xx  R1(config-router)#neighbor x.1.1.9 password yyyyyyyy  R1(config-router)#neighbor x.2.1.7 password zzzzzzzzz     Internal Only - General",
    cci: "CCI-002205",
    expectedState: "Configure the router to use unique keys for each AS that it peers with as shown in the example below.",
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
