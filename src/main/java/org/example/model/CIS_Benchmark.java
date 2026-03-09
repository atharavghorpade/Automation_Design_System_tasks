package org.example.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CIS_Benchmark {

    // Allowed values
    private static final String LEVEL_1 = "1";
    private static final String LEVEL_2 = "2";

    private String ruleNumber;     // REQUIRED
    private String title;          // REQUIRED
    private String level;          // REQUIRED (1 or 2)
    private String profile;        // REQUIRED
    private String description;
    private String rationale;  // Optional but often present
    private String impact;
    private String audit;          // REQUIRED
    private String remediation;    // REQUIRED
    private String defaultValue;
    private String references;
    private String expectedState;

    public CIS_Benchmark() {
    }

    // ---------------- Validation Helper ----------------
    private String clean(String value) {
        return value == null ? null : value.trim();
    }

    // ---------------- Rule Number ----------------
    public String getRuleNumber() {
        return ruleNumber;
    }

    public void setRuleNumber(String ruleNumber) {
        ruleNumber = clean(ruleNumber);
        if (ruleNumber == null || ruleNumber.isEmpty()) {
            throw new IllegalArgumentException("Rule Number is mandatory.");
        }
        this.ruleNumber = ruleNumber;
    }

    // ---------------- Title ----------------
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        title = clean(title);
        if (title == null || title.isEmpty()) {
            throw new IllegalArgumentException("Title is mandatory.");
        }
        this.title = title;
    }

    // ---------------- Level ----------------
    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        level = clean(level);

        if (level == null) {
            throw new IllegalArgumentException("Level is mandatory.");
        }

        // Normalize real CIS text formats
        if (level.contains("1")) {
            this.level = "1";
        }
        else if (level.contains("2")) {
            this.level = "2";
        }
        else {
            throw new IllegalArgumentException(
                    "Invalid Level value: " + level
            );
        }
    }

    // ---------------- Profile ----------------
    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        profile = clean(profile);
        if (profile == null || profile.isEmpty()) {
            throw new IllegalArgumentException("Profile is mandatory.");
        }
        this.profile = profile;
    }

    // ---------------- Description ----------------
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = clean(description);
    }

    // ---------------- Rationale ----------------
    public String getRationale() {
        return rationale;
    }

    public void setRationale(String rationale) {
        this.rationale = clean(rationale);
    }

    // ---------------- Impact ----------------
    public String getImpact() {
        return impact;
    }

    public void setImpact(String impact) {
        this.impact = clean(impact);
    }

    // ---------------- Audit ----------------
    public String getAudit() {
        return audit;
    }

    public void setAudit(String audit) {
        audit = clean(audit);
        if (audit == null || audit.isEmpty()) {
            throw new IllegalArgumentException("Audit field is mandatory.");
        }
        this.audit = audit;
    }

    // ---------------- Remediation ----------------
    public String getRemediation() {
        return remediation;
    }

    public void setRemediation(String remediation) {
        remediation = clean(remediation);
        if (remediation == null || remediation.isEmpty()) {
            throw new IllegalArgumentException("Remediation field is mandatory.");
        }
        this.remediation = remediation;
    }

    // ---------------- Optional Fields ----------------
    public String getDefaultValue() {
        return defaultValue;
    }

    public void setDefaultValue(String defaultValue) {
        this.defaultValue = clean(defaultValue);
    }

    public String getReferences() {
        return references;
    }

    public void setReferences(String references) {
        this.references = clean(references);
    }

    public String getExpectedState() {
        return expectedState;
    }

    public void setExpectedState(String expectedState) {
        this.expectedState = clean(expectedState);
    }
}
