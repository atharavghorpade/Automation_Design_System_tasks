var metadata = {
    groupIdNumber: "1.4",
    stigId: "CISC-RT-000090",
    ruleId: "RULE ID: SV-216559r856180",
    groupId: "GROUP ID: V-216559",
    severity: "HIGH",
    description: "The Cisco router must not be configured to have any zero-touch deployment feature  enabled when connected to an operational network.  GROUP ID: V-216559  RULE ID: SV-216559r856180",
    rationale: "Network devices that are configured via a zero-touch deployment or auto-loading  feature can have their startup configuration or image pushed to the device for  installation via TFTP or Remote Copy (rcp). Loading an image or configuration file from  the network is taking a security risk because the file could be intercepted by an attacker  who could corrupt the file, resulting in a denial of service.",
    audit: "Review the device configuration to determine if auto-configuration or zero-touch  deployment via Cisco Networking Services (CNS) is enabled.  Auto-configuration example  version 15.0  service config  …  …  …  boot-start-marker  boot network tftp://x.x.x.x/R5-config  boot-end-marker  CNS Zero-Touch Example  cns trusted-server config x.x.x.x  cns trusted-server image x.x.x.x  cns config initial x.x.x.x 80  cns exec 80  cns image  If a configuration auto-loading feature or zero-touch deployment feature is enabled, this  is a finding.  Note: Auto-configuration or zero-touch deployment features can be enabled when the  router is offline for the purpose of image loading or building out the configuration. In  addition, this would not be applicable to the provisioning of virtual routers via a software- defined network (SDN) orchestration system.  Internal Only - General",
    remediation: "Disable configuration auto-loading if enabled using the following commands.  R8(config)#no boot network  R8(config)#no service config  Disable CNS zero-touch deployment if enabled as shown in the example below.  R2(config)#no cns config initial  R2(config)#no cns exec  R2(config)#no cns image  R2(config)#no cns trusted-server config x.x.x.x  R2(config)#no cns trusted-server image x.x.x.x",
    cci: "CCI-002385",
    expectedState: "Disable configuration auto-loading if enabled using the following commands.",
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

    if ("equals:true" === "not_exists") {
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
