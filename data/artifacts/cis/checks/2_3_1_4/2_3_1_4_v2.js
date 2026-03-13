var metadata = {
    ruleNumber: "2.3.1.4",
    title: "Set 'key' for each 'ntp server' (Automated)",
    profile: "• Level 2",
    description: "Specifies the authentication key for NTP.",
    rationale: "This authentication feature provides protection against accidentally synchronizing the ntp system to another system that is not trusted, because the other system must know the correct authentication key.",
    impact: "Organizations should establish three Network Time Protocol (NTP) hosts to set consistent time across the enterprise. Enabling the 'ntp server key' command enforces encrypted authentication between NTP hosts.",
    audit: "From the command prompt, execute the following commands: hostname#show run | include ntp server",
    remediation: "Configure each NTP Server to use a key ring using the following command. hostname(config)#ntp server {<em>ntp-server_ip_address</em>}{key <em>ntp_key_id</em>}",
    defaultValue: "No NTP key is set by default CIS Controls: Controls Version Control IG 1 IG 2 IG 3 v8",
    expectedState: "No NTP key is set by default CIS Controls: Controls Version Control IG 1 IG 2 IG 3 v8",
    generatedOn: "2026-03-13",
    generatorVersion: "2.1",
    benchmark: "CIS"
};
// -----------------------------------------------------------

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

        if (line.indexOf("no ntp".toLowerCase()) !== -1) {

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
