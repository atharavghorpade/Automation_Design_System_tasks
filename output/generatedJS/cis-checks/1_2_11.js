var metadata = {
    ruleNumber: "1.2.11",
    title: "Set 'exec-timeout' to less than or equal to 10 min on 'ip",
    profile: "• Level 1",
    description: "If no input is detected during the interval, the EXEC facility resumes the current connection. If no connections exist, the EXEC facility returns the terminal to the idle state and disconnects the incoming session.",
    rationale: "This prevents unauthorized users from misusing abandoned sessions. For example, if the network administrator leaves for the day and leaves a computer open with an enabled login session accessible. There is a trade-off here between security (shorter timeouts) and usability (longer timeouts). Review your local policies and operational needs to determine the best timeout value. In most cases, this should be no more than 10 minutes. This prevents unauthorized users from misusing abandoned sessions. For example, if the network administrator leaves for the day and leaves a computer open with an enabled login session accessible. There is a trade-off here between security (shorter timeouts) and usability (longer timeouts). Review your local policies and operational needs to determine the best timeout value. In most cases, this should be no more than 10 minutes.",
    impact: "",
    audit: "Perform the following to determine if the timeout is configured: sh run | beg ip http timeout-policy",
    remediation: "Configure device timeout (10 minutes or less) to disconnect sessions after a fixed idle time. ip http timeout-policy idle 600 life {nnnn} requests {nn}",
    defaultValue: "disabled Page 56",
    expectedState: "disabled Page 56",
<<<<<<< HEAD
    generatedOn: "2026-03-09",
=======
    generatedOn: "2026-03-10",
>>>>>>> bd8ffc79618740127f9ddfcd8161efa6174d898f
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

        if (line.indexOf("###NO_MATCH###".toLowerCase()) !== -1) {

            matched = true;
            foundLine = i + 1;

            var numberMatch = line.match(/\d+/);
            var actual = numberMatch ? parseInt(numberMatch[0]) : null;

            pass = (line.indexOf('no ') === 0);
        }
    }

    if ("equals:false" === "not_exists") {
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
