var metadata = {
    groupIdNumber: "1.14",
    stigId: "CISC-RT-000230",
    ruleId: "RULE ID: SV-216571r531085",
    groupId: "GROUP ID: V-216571",
    severity: "HIGH",
    description: "The Cisco router must be configured to disable the auxiliary port unless it is connected  to a secured modem providing encryption and authentication.  GROUP ID: V-216571  RULE ID: SV-216571r531085",
    rationale: "The use of POTS lines to modems connecting to network devices provides clear text of  authentication traffic over commercial circuits that could be captured and used to  compromise the network. Additional war dial attacks on the device could degrade the  device and the production network.  Secured modem devices must be able to authenticate users and must negotiate a key  exchange before full encryption takes place. The modem will provide full encryption  capability (Triple DES) or stronger. The technician who manages these devices will be  authenticated using a key fob and granted access to the appropriate maintenance port;  thus, the technician will gain access to the managed device (router, switch, etc.). The  token provides a method of strong (two-factor) user authentication. The token works in  conjunction with a server to generate one-time user passwords that will change values  at second intervals. The user must know a personal identification number (PIN) and  possess the token to be allowed access to the device.",
    audit: "Review the configuration and verify that the auxiliary port is disabled unless a secured  modem providing encryption and authentication is connected to it.  line aux 0  no exec  Note: transport input none is the default, hence it will not be shown in the configuration.  If the auxiliary port is not disabled or is not connected to a secured modem when it is  enabled, this is a finding.",
    remediation: "Disable the auxiliary port.  R2(config)#line aux 0  R2(config-line)#no exec  R2(config-line)#transport input none  Internal Only - General",
    cci: "CCI-001414",
    expectedState: "Disable the auxiliary port.",
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
