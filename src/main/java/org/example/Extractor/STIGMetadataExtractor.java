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

                // Correct severity extraction
                meta.setSeverity(extract(block, "SEVERITY:\\s*(CAT\\s+(?:I|II|III))"));

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

                // Keep parity with CIS extraction by populating expected state.
                meta.setExpectedState(inferExpectedStateForSTIG(meta));

                result.add(meta);
            }
        }

        return result;
    }

    private String extract(String text, String regex) {

        Matcher m = Pattern
                .compile(regex, Pattern.MULTILINE | Pattern.CASE_INSENSITIVE)
                .matcher(text);
        return m.find() ? m.group().trim() : null;
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

        return m.find() ? m.group(1).trim() : null;
    }

    // Heuristic inference for expected state (similar to CISMetadataExtractor)
    private String inferExpectedStateForSTIG(STIG_Benchmark b) {
        String s = null;

        // Prefer remediation then audit, then description, then rationale
        if (b.getRemediation() != null && !b.getRemediation().isEmpty()) s = b.getRemediation();
        if ((s == null || s.isEmpty()) && b.getAudit() != null && !b.getAudit().isEmpty()) s = b.getAudit();
        if ((s == null || s.isEmpty()) && b.getDescription() != null && !b.getDescription().isEmpty()) s = b.getDescription();
        if ((s == null || s.isEmpty()) && b.getRationale() != null && !b.getRationale().isEmpty()) s = b.getRationale();

        if (s == null) return null;

        s = s.replaceAll("\\s+", " ").trim();

        String[] sentences = s.split("(?<=[.?!])\\s+");

        Pattern verbLike = Pattern.compile("\\b(should|must|configure|set|enable|disable|ensure|remove|deny|allow|restart|apply)\\b", Pattern.CASE_INSENSITIVE);
        for (String sent : sentences) {
            if (verbLike.matcher(sent).find()) {
                return sent.trim();
            }
        }

        return null;
    }
} 