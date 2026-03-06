package org.example.Extractor;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.example.model.STIG_Benchmark;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class STIGMetadataExtractor {

    public List<STIG_Benchmark> extract(File pdfFile) throws Exception {

        List<STIG_Benchmark> result = new ArrayList<>();

        try (PDDocument document = PDDocument.load(pdfFile)) {

            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document);

            // Normalize text
            text = text.replaceAll("\\r", "");
            text = text.replaceAll("Page \\d+\\s*", "");
            text = text.replaceAll("\\n{2,}", "\n");

            // Pattern to capture rule blocks like 1.1, 2.4 etc
            Pattern rulePattern = Pattern.compile(
                    "^\\d+\\.\\d+\\s+.*?(?=^\\d+\\.\\d+\\s+|\\Z)",
                    Pattern.MULTILINE | Pattern.DOTALL
            );

            Matcher matcher = rulePattern.matcher(text);

            while (matcher.find()) {

                String block = matcher.group().trim();

                // Only process valid STIG blocks
                if (!block.contains("GROUP ID")) continue;

                STIG_Benchmark meta = new STIG_Benchmark();

                // Extract numeric group index (1.1, 2.3 etc)
                meta.setGroupIdNumber(extract(block, "^\\d+\\.\\d+"));

                // STIG ID (CISC-RT-000010)
                meta.setStigId(extract(block, "CISC-RT-\\d+"));

                // Extract clean GROUP ID value
                meta.setGroupId(extract(block, "GROUP ID:\\s*(V-\\d+)"));

                // Extract clean RULE ID value
                meta.setRuleId(extract(block, "RULE ID:\\s*(SV-\\d+r\\d+)"));

                // Extract severity category
                String severity = extract(block, "SEVERITY:\\s*(CAT\\s+(?:I|II|III))");

                if (severity != null) {
                    meta.setSeverity(severity); 
                    meta.setSeverityCategory("SEVERITY: " + severity);
                }

                // Extract CCI values
                meta.setCci(extractAll(block, "CCI-\\d+"));

                // Extract sections
                meta.setDescription(
                        extractSection(block, "Description:", "Rationale:")
                );

                meta.setRationale(
                        extractSection(block, "Rationale:", "Audit:")
                );

                meta.setAudit(
                        extractSection(block, "Audit:", "Remediation:")
                );

                meta.setRemediation(
                        extractSection(block, "Remediation:", "Additional Information:")
                );

                result.add(meta);
            }
        }

        return result;
    }

    private String extract(String text, String regex) {

        Matcher m = Pattern
                .compile(regex, Pattern.MULTILINE | Pattern.CASE_INSENSITIVE)
                .matcher(text);

        if (m.find()) {
            if (m.groupCount() >= 1) {
                String captured = m.group(1);
                if (captured != null) {
                    return captured.trim();
                }
            }
            return m.group().trim();
        }

        return null;
    }

    // Extract multiple CCI values
    private String extractAll(String text, String regex) {

        Matcher m = Pattern.compile(regex).matcher(text);

        StringBuilder sb = new StringBuilder();

        while (m.find()) {
            sb.append(m.group()).append(", ");
        }

        if (sb.length() > 0) {
            return sb.substring(0, sb.length() - 2);
        }

        return null;
    }

    private String extractSection(String text, String start, String end) {

        Pattern p = Pattern.compile(
                Pattern.quote(start) + "(.*?)" + Pattern.quote(end),
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE
        );

        Matcher m = p.matcher(text);

        if (m.find()) {
            return m.group(1)
                    .replaceAll("\\s+\\n", " ")
                    .replaceAll("\\n", " ")
                    .trim();
        }

        return null;
    }
} 