package org.example.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class STIG_Benchmark {

    // Allowed severity values
    private static final String LOW = "LOW";
    private static final String MEDIUM = "MEDIUM";
    private static final String HIGH = "HIGH";

    private String groupIdNumber;
    private String stigId;        // REQUIRED
    private String ruleId;        // REQUIRED
    private String groupId;
    private String severity;      // REQUIRED (LOW/MEDIUM/HIGH)
    private String description;   // REQUIRED
    private String rationale;
    private String audit;         // REQUIRED
    private String remediation;   // REQUIRED
    private String cci;
    private String expectedState;

    public STIG_Benchmark() {
    }

    // ---------------- Utility ----------------
    private String clean(String value) {
        return value == null ? null : value.trim();
    }

    // ---------------- Group ID Number ----------------
    public String getGroupIdNumber() {
        return groupIdNumber;
    }

    public void setGroupIdNumber(String groupIdNumber) {
        this.groupIdNumber = clean(groupIdNumber);
    }

    // ---------------- STIG ID ----------------
    public String getStigId() {
        return stigId;
    }

    public void setStigId(String stigId) {
        stigId = clean(stigId);
        if (stigId == null || stigId.isEmpty()) {
            throw new IllegalArgumentException("STIG ID is mandatory.");
        }
        this.stigId = stigId;
    }

    // ---------------- Rule ID ----------------
    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        ruleId = clean(ruleId);
        if (ruleId == null || ruleId.isEmpty()) {
            throw new IllegalArgumentException("Rule ID is mandatory.");
        }
        this.ruleId = ruleId;
    }

    // ---------------- Group ID ----------------
    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = clean(groupId);
    }

    // ---------------- Severity ----------------
    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {

        severity = clean(severity);

        if (severity == null) {
            throw new IllegalArgumentException("Severity is mandatory.");
        }

        severity = severity.toUpperCase();

        // Handle STIG Category format
        if (severity.contains("CAT I") || severity.contains("CATEGORY I")) {
            this.severity = "HIGH";
        }
        else if (severity.contains("CAT II") || severity.contains("CATEGORY II")) {
            this.severity = "MEDIUM";
        }
        else if (severity.contains("CAT III") || severity.contains("CATEGORY III")) {
            this.severity = "LOW";
        }

        // Handle direct HIGH/MEDIUM/LOW
        else if (severity.contains("HIGH")) {
            this.severity = "HIGH";
        }
        else if (severity.contains("MEDIUM")) {
            this.severity = "MEDIUM";
        }
        else if (severity.contains("LOW")) {
            this.severity = "LOW";
        }
        else {
            throw new IllegalArgumentException(
                    "Invalid Severity value: " + severity
            );
        }
    }

    // ---------------- Description ----------------
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        description = clean(description);
        if (description == null || description.isEmpty()) {
            throw new IllegalArgumentException("Description is mandatory.");
        }
        this.description = description;
    }

    // ---------------- Rationale ----------------
    public String getRationale() {
        return rationale;
    }

    public void setRationale(String rationale) {
        this.rationale = clean(rationale);
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

    // ---------------- CCI ----------------
    public String getCci() {
        return cci;
    }

    public void setCci(String cci) {
        this.cci = clean(cci);
    }

    // ---------------- Expected State ----------------
    public String getExpectedState() {
        return expectedState;
    }

    public void setExpectedState(String expectedState) {
        this.expectedState = clean(expectedState);
    }
}
