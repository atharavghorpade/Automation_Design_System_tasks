package org.example.Generator;

import org.example.model.STIG_Benchmark;

import java.io.File;
import java.io.FileWriter;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class STIG_checkGenerator {

    public static void generateChecks(List<STIG_Benchmark> rules) throws Exception {

        File folder = new File("output/generatedJS/stig-checks");

        if (!folder.exists()) {
            folder.mkdirs();
        }

        for (STIG_Benchmark rule : rules) {

            String fileName = "output/generatedJS/stig-checks/"
                    + safeFileName(rule.getGroupId()) + ".js";

            try (FileWriter writer = new FileWriter(fileName)) {
                writer.write(generateJsContent(rule));
            }
        }
    }

    private static String generateJsContent(STIG_Benchmark rule) {

        String functionId = safeFunctionName(rule.getGroupId());
        String ruleFunction = safeFunctionName(rule.getRuleId());

        String audit = rule.getAudit() == null ? "" : rule.getAudit();

        String keyPhrase = extractKeyPhrase(audit);

        return """
// ── STIG SECURITY CONTROL METADATA ──────────────────────────
var metadata = {
    framework: "STIG",
    checkType: "SECURITY_CONTROL",
    groupIdNumber: "%s",
    stigId: "%s",
    ruleId: "%s",
    groupId: "%s",
    severity: "%s",
    severityCategory: "%s",
    description: "%s",
    rationale: "%s",
    auditProcedure: "%s",
    remediation: "%s",
    cci: "%s",
    expectedState: "%s",
    generatedOn: "%s",
    generatorVersion: "2.1",
    benchmark: "STIG",
    checkFormat: "STIG_CONTROL"
};


// ── EVALUATION FUNCTION ─────────────────────────────────────
function evaluateSTIGControl_%s(config) {

    if (!config) {
        return {
            status: "ERROR",
            stigId: metadata.stigId,
            cci: metadata.cci,
            severity: metadata.severity,
            line: 0,
            framework: "STIG",
            category: metadata.severityCategory
        };
    }

    var lines = String(config).split("\\n");
    var matched = false;
    var foundLine = 0;

    for (var i = 0; i < lines.length; i++) {

        var line = lines[i].toLowerCase();

        if (line.indexOf("%s".toLowerCase()) !== -1) {

            matched = true;
            foundLine = i + 1;
        }
    }

    if (!matched) {

        return {
            status: "FAIL",
            stigId: metadata.stigId,
            cci: metadata.cci,
            severity: metadata.severity,
            line: 0,
            framework: "STIG",
            category: metadata.severityCategory
        };
    }

    return {
        status: "PASS",
        stigId: metadata.stigId,
        cci: metadata.cci,
        severity: metadata.severity,
        line: foundLine,
        framework: "STIG",
        category: metadata.severityCategory
    };
}


// ── ALIAS FUNCTION ──────────────────────────────────────────
function check_%s(config) {
    return evaluateSTIGControl_%s(config);
}


// ── MODULE EXPORT ───────────────────────────────────────────
module.exports = {
    evaluateSTIGControl_%s: evaluateSTIGControl_%s,
    check_%s: check_%s
};
""".formatted(

                UUID.randomUUID(),
                safe(rule.getStigId()),
                safe(rule.getRuleId()),
                safe(rule.getGroupId()),
                safe(rule.getSeverity()),
                safe(rule.getSeverity()),
                safe(rule.getDescription()),
                safe(rule.getRationale()),
                safe(rule.getAudit()),
                safe(rule.getRemediation()),
                safe(rule.getCci()),
                safe(rule.getRuleId()),
                Instant.now().toString(),

                functionId,
                safe(keyPhrase),

                ruleFunction,
                functionId,

                functionId,
                functionId,
                ruleFunction,
                ruleFunction
        );
    }

    // -------------------------------------------------
    // Extract CLI phrase
    // -------------------------------------------------

    private static String extractKeyPhrase(String text) {

        if (text == null) return "";

        text = text.toLowerCase();

        if (text.contains("access-list"))
            return "access-list";

        if (text.contains("service password-encryption"))
            return "service password-encryption";

        if (text.contains("snmp-server"))
            return "snmp-server";

        if (text.contains("logging"))
            return "logging";

        return "";
    }

    // -------------------------------------------------
    // Utilities
    // -------------------------------------------------

    private static String safe(String value) {

        if (value == null) return "";

        return value.replace("\"", "\\\"")
                .replace("\n", " ")
                .replace("\r", " ");
    }

    private static String safeFileName(String value) {

        if (value == null) return "unknown_rule";

        return value.replace(".", "_")
                .replace("/", "_")
                .replace(" ", "_")
                .replace("-", "_");
    }

    private static String safeFunctionName(String value) {

        if (value == null) return "unknown_rule";

        return value.replace("-", "_")
                .replace(" ", "_")
                .replace(".", "_");
    }
}