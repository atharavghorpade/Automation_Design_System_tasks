package org.example.Extractor;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.example.model.CIS_Benchmark;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CISMetadataExtractor {

    private static final List<String> SECTION_HEADERS = Arrays.asList(
            "Profile Applicability",
            "Description",
            "Rationale",
            "Impact",
            "Audit",
            "Remediation",
            "Default Value",
            "References"
    );

    public List<CIS_Benchmark> extract(File pdfFile) throws IOException {

        List<CIS_Benchmark> result = new ArrayList<>();

        try (PDDocument document = PDDocument.load(pdfFile)) {

            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document);

            text = normalize(text);

            List<String> ruleBlocks = splitIntoRuleBlocks(text);

            boolean startProcessing = false;

            for (String block : ruleBlocks) {

                String ruleNumber = extractRuleNumber(block);

                // Start only from 1.1.1
                if ("1.1.1".equals(ruleNumber)) {
                    startProcessing = true;
                }

                if (!startProcessing) {
                    continue;
                }

                CIS_Benchmark meta = parseRuleBlock(block);

                if (meta != null && meta.getRuleNumber() != null) {
                    result.add(meta);
                }
            }
        }

        return result;
    }

    /* ---------------------------------------------------- */

    private String normalize(String text) {
        return text.replace("\r", "")
                .replaceAll("[ \\t]+", " ")
                .trim();
    }

    /* ---------------------------------------------------- */

    private List<String> splitIntoRuleBlocks(String text) {

        List<String> blocks = new ArrayList<>();

        Pattern rulePattern = Pattern.compile(
                "^\\d+(?:\\.\\d+)+\\s+.*?(?=^\\d+(?:\\.\\d+)+\\s+|\\Z)",
                Pattern.MULTILINE | Pattern.DOTALL
        );

        Matcher matcher = rulePattern.matcher(text);

        while (matcher.find()) {
            blocks.add(matcher.group().trim());
        }

        return blocks;
    }

    /* ---------------------------------------------------- */

    private CIS_Benchmark parseRuleBlock(String block) {

        String ruleNumber = extractRuleNumber(block);

        if (ruleNumber == null)
            return null;

        // Must follow format like 1.1.1
        if (!ruleNumber.matches("\\d+\\.\\d+\\.\\d+.*"))
            return null;

        if (!block.toLowerCase().contains("description:"))
            return null;

        CIS_Benchmark meta = new CIS_Benchmark();

        meta.setRuleNumber(ruleNumber);
        meta.setTitle(extractTitle(block));
        meta.setLevel(extractLevel(block));

        Map<String, String> sections = extractSections(block);

        // Validate minimum required sections
        if (sections.get("Description") == null ||
                sections.get("Audit") == null) {
            return null;
        }

        meta.setProfile(sections.get("Profile Applicability"));
        meta.setDescription(sections.get("Description"));
        meta.setRationale(sections.get("Rationale"));
        meta.setImpact(sections.get("Impact"));
        meta.setAudit(sections.get("Audit"));
        meta.setRemediation(sections.get("Remediation"));
        meta.setDefaultValue(sections.get("Default Value"));
        meta.setReferences(sections.get("References"));

        meta.setExpectedState(inferExpectedState(meta));

        return meta;
    }

    /* ---------------------------------------------------- */

    private String extractRuleNumber(String text) {
        Matcher m = Pattern.compile("^\\d+(?:\\.\\d+)+", Pattern.MULTILINE).matcher(text);
        return m.find() ? m.group().trim() : null;
    }

    private String extractTitle(String block) {
        String firstLine = block.split("\\n")[0];
        return firstLine.replaceFirst("^\\d+(?:\\.\\d+)+\\s*", "").trim();
    }

    /* ---------------------------------------------------- */

    private String extractLevel(String block) {
        Pattern levelPattern = Pattern.compile("\\b(Level\\s+[12])\\b", Pattern.CASE_INSENSITIVE);
        Matcher m = levelPattern.matcher(block);
        return m.find() ? m.group(1) : null;
    }

    /* ---------------------------------------------------- */

    private Map<String, String> extractSections(String block) {

        Map<String, String> sections = new HashMap<>();

        for (int i = 0; i < SECTION_HEADERS.size(); i++) {

            String startHeader = SECTION_HEADERS.get(i);
            Pattern startPattern = Pattern.compile("(?i)" + Pattern.quote(startHeader) + "\\s*:");
            Matcher startMatcher = startPattern.matcher(block);

            if (!startMatcher.find())
                continue;

            int startIndex = startMatcher.end();
            int endIndex = block.length();

            for (int j = i + 1; j < SECTION_HEADERS.size(); j++) {

                String nextHeader = SECTION_HEADERS.get(j);
                Pattern nextPattern = Pattern.compile("(?i)" + Pattern.quote(nextHeader) + "\\s*:");
                Matcher nextMatcher = nextPattern.matcher(block);

                if (nextMatcher.find(startIndex)) {
                    endIndex = nextMatcher.start();
                    break;
                }
            }

            String content = block.substring(startIndex, endIndex).trim();
            content = content.replaceAll("\\s+", " ");

            sections.put(startHeader, content);
        }

        return sections;
    }

    /* ---------------------------------------------------- */

    private String inferExpectedState(CIS_Benchmark b) {

        List<String> priorityFields = Arrays.asList(
                b.getDefaultValue(),
                b.getRemediation(),
                b.getAudit(),
                b.getDescription(),
                b.getRationale()
        );

        Pattern verbLike = Pattern.compile(
                "\\b(should|must|configure|set|enable|disable|ensure|remove|deny|allow|restart|apply)\\b",
                Pattern.CASE_INSENSITIVE
        );

        for (String field : priorityFields) {

            if (field == null || field.isEmpty())
                continue;

            String cleaned = field.replaceAll("\\s+", " ").trim();

            String[] sentences = cleaned.split("(?<=[.?!])\\s+");

            for (String sentence : sentences) {
                if (verbLike.matcher(sentence).find()) {
                    return sentence.trim();
                }
            }

            return sentences[0].trim();
        }

        return null;
    }
}
