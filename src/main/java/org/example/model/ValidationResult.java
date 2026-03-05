package org.example.model;

public class ValidationResult {

    private String ruleId;
    private String status;
    private int line;
    private boolean matched;

    public ValidationResult(String ruleId, String status, int line, boolean matched) {
        this.ruleId = ruleId;
        this.status = status;
        this.line = line;
        this.matched = matched;
    }

    public String getRuleId() { return ruleId; }
    public String getStatus() { return status; }
    public int getLine() { return line; }
    public boolean isMatched() { return matched; }
}
