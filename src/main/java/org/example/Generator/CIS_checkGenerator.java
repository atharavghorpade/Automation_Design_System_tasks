package org.example.Generator;

import org.example.model.CIS_Benchmark;

import java.io.File;
import java.io.FileWriter;
import java.time.LocalDate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class CIS_checkGenerator {  

    public static void generateChecks(List<CIS_Benchmark> rules) throws Exception {

        File folder = new File("output/generatedJS/cis-checks");
        if (!folder.exists()) {
            folder.mkdirs();
        }

        int generatedCount = 0;

        for (CIS_Benchmark rule : rules) {

            if (rule.getRuleNumber() == null || rule.getRuleNumber().isBlank()) {
                continue;
            }

            String fileName = "output/generatedJS/cis-checks/"
                    + safeFileName(rule.getRuleNumber()) + ".js";

            try (FileWriter writer = new FileWriter(fileName)) {
                writer.write(generateJsContent(rule));
                generatedCount++;
            }
        }

        System.out.println("Total CIS JS files generated: " + generatedCount);
    }

    /* ========================================================= */

    private static String generateJsContent(CIS_Benchmark rule) {


        String expected = rule.getExpectedState();
        if (expected == null || expected.isBlank()) {
            expected = "Configuration must match CIS compliance requirement";
        }

        String remediation = rule.getRemediation();
        if (remediation == null || remediation.isBlank()) {
            remediation = "Apply configuration as per CIS guideline";
        }

        String audit = rule.getAudit();
        if (audit == null || audit.isBlank()) {
            audit = "Verify configuration manually";
        }

        /* ----------------------------------------------------------- */

        String operator = detectOperator(expected);
        String expectedValue = extractNumber(expected);
        String keyPhrase = extractKeyPhrase(rule);

        if (keyPhrase.isEmpty()) {
            keyPhrase = "###NO_MATCH###";
        }

        String generatedDate = LocalDate.now().toString();

        return """
            var metadata = {
                ruleNumber: "%s",
                title: "%s",
                profile: "%s",
                description: "%s",
                rationale: "%s",
                impact: "%s",
                audit: "%s",
                remediation: "%s",
                defaultValue: "%s",
                expectedState: "%s",
                generatedOn: "%s",
                generatorVersion: "2.1",
                benchmark: "CIS"
            };

            function check(config) {

                if (!config) {
                    return { status: "ERROR", line: 0 };
                }

                var lines = String(config).split("\\n");
                var matched = false;
                var foundLine = 0;
                var pass = true;

                for (var i = 0; i < lines.length; i++) {

                    var line = lines[i].toLowerCase();

                    if (line.indexOf("%s".toLowerCase()) !== -1) {

                        matched = true;
                        foundLine = i + 1;

                        var numberMatch = line.match(/\\d+/);
                        var actual = numberMatch ? parseInt(numberMatch[0]) : null;

                        %s
                    }
                }

                if ("%s" === "not_exists") {
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
            """.formatted(
                safe(rule.getRuleNumber()),
                safe(rule.getTitle()),
                safe(rule.getProfile()),
                safe(rule.getDescription()),
                safe(rule.getRationale()),
                safe(rule.getImpact()),
                safe(audit),
                safe(remediation),
                safe(rule.getDefaultValue()),
                safe(expected),
                generatedDate,
                safe(keyPhrase),
                generateComparisonLogic(operator, expectedValue),
                operator
        );
    }

    /* ========================================================= */

    private static String detectOperator(String text) {

        if (text == null) return "exists";

        text = text.toLowerCase();

        if (text.contains("must not exist") || text.contains("not be present"))
            return "not_exists";

        if (text.contains("at least") || text.contains("or more"))
            return ">=";

        if (text.contains("greater than"))
            return ">";

        if (text.contains("less than"))
            return "<";

        if (text.contains("or less"))
            return "<=";

        if (text.contains("disabled"))
            return "equals:false";

        if (text.contains("enabled"))
            return "equals:true";

        return "exists";
    }

    private static String extractNumber(String text) {

        if (text == null) return "";

        Matcher m = Pattern.compile("(\\d+)").matcher(text);
        return m.find() ? m.group(1) : "";
    }

    private static String extractKeyPhrase(CIS_Benchmark rule) {

        if (rule.getAudit() != null) {
            Matcher quoted = Pattern.compile("'([^']+)'")
                    .matcher(rule.getAudit());
            if (quoted.find()) {
                return quoted.group(1).trim();
            }
        }

        if (rule.getExpectedState() != null) {

            String text = rule.getExpectedState().toLowerCase();

            Matcher cmd = Pattern.compile(
                    "(service\\s+\\S+|ip\\s+\\S+|logging\\s+\\S+|snmp-server\\s+\\S+|interface\\s+\\S+|no\\s+\\S+)",
                    Pattern.CASE_INSENSITIVE
            ).matcher(text);

            if (cmd.find()) {
                return cmd.group(1).trim();
            }
        }

        return "";
    }

    private static String generateComparisonLogic(String operator, String value) {

        if (value.isEmpty()) {
            return "pass = true;";
        }

        if (operator.equals(">="))
            return "pass = (actual !== null && actual >= " + value + ");";

        if (operator.equals(">"))
            return "pass = (actual !== null && actual > " + value + ");";

        if (operator.equals("<"))
            return "pass = (actual !== null && actual < " + value + ");";

        if (operator.equals("<="))
            return "pass = (actual !== null && actual <= " + value + ");";

        if (operator.equals("equals:true"))
            return "pass = (line.indexOf('no ') !== 0);";

        if (operator.equals("equals:false"))
            return "pass = (line.indexOf('no ') === 0);";

        return "pass = true;";
    }

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
                .replace(" ", "_");
    }
}