package org.example.runner;
import org.graalvm.polyglot.*;
import org.graalvm.polyglot.proxy.*;
import javax.script.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;



public class JSValidationRunner {

    public static void runValidation() throws Exception {

        String configFolder = "input/device-config";

        String stigFolder = "output/generatedJS/stig-checks";
        String cisFolder = "output/generatedJS/cis-checks";

        File folder = new File(configFolder);

        File[] configFiles = folder.listFiles((dir, name) -> name.endsWith(".cfg"));

        if (configFiles == null || configFiles.length == 0) {
            System.out.println("No config files found.");
            return;
        }

        for (File configFile : configFiles) {

            System.out.println("Validating: " + configFile.getName());

            String deviceConfig = Files.readString(
                    configFile.toPath(),
                    java.nio.charset.StandardCharsets.UTF_8
            );

            List<Map<String, String>> stigResults =
                    runChecks(stigFolder, deviceConfig);

            List<Map<String, String>> cisResults =
                    runChecks(cisFolder, deviceConfig);

            String deviceName = configFile.getName().replace(".cfg", "");

            writeJson("STIG",
                    stigResults,
                    "output/reports/" + deviceName + "-stig-report.json");

            writeJson("CIS",
                    cisResults,
                    "output/reports/" + deviceName + "-cis-report.json");
        }

        System.out.println("Validation completed for all devices.");
    }

    private static List<Map<String, String>> runChecks(String folderPath,
                                                       String deviceConfig) throws Exception {

        List<Map<String, String>> results = new ArrayList<>();

        File folder = new File(folderPath);

        if (!folder.exists()) {
            System.out.println("Folder not found: " + folder.getAbsolutePath());
            return results;
        }

        File[] jsFiles = folder.listFiles((dir, name) -> name.endsWith(".js"));

        if (jsFiles == null || jsFiles.length == 0) {
            System.out.println("No JS files found in: " + folder.getAbsolutePath());
            return results;
        }

        // 🔥 Sort files for deterministic execution
        Arrays.sort(jsFiles, Comparator.comparing(File::getName));

        for (File jsFile : jsFiles) {

            Map<String, String> ruleResult = new HashMap<>();
            String ruleId = jsFile.getName().replace(".js", "");
            ruleResult.put("ruleId", ruleId);

            try (Context context = Context.newBuilder("js")
                    .allowAllAccess(true)
                    .build()) {

                // Inject config variable
                context.getBindings("js").putMember("config", deviceConfig);

                String script = Files.readString(jsFile.toPath());

                Value result = context.eval("js", script);

                if (result.hasMembers()) {

                    String status = result.getMember("status") != null
                            ? result.getMember("status").asString()
                            : "ERROR";

                    String line = result.getMember("line") != null
                            ? result.getMember("line").toString()
                            : "0";

                    ruleResult.put("status", status);
                    ruleResult.put("line", line);

                } else if (!result.isNull()) {

                    ruleResult.put("status", result.toString());
                    ruleResult.put("line", "0");

                } else {

                    ruleResult.put("status", "ERROR");
                    ruleResult.put("line", "0");
                }

            } catch (Exception e) {

                ruleResult.put("status", "ERROR");
                ruleResult.put("line", "0");
                e.printStackTrace();
            }

            results.add(ruleResult);
        }

        return results;
    }
    private static void writeJson(String type,
                                  List<Map<String, String>> results,
                                  String filePath) throws Exception {

        File folder = new File("output/reports");
        if (!folder.exists()) folder.mkdirs();

        int pass = 0;
        int fail = 0;
        int error = 0;

        for (Map<String, String> r : results) {
            String status = r.get("status");
            if ("PASS".equalsIgnoreCase(status)) pass++;
            else if ("FAIL".equalsIgnoreCase(status)) fail++;
            else error++;
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"type\": \"").append(type).append("\",\n");
        json.append("  \"summary\": {\n");
        json.append("    \"total\": ").append(results.size()).append(",\n");
        json.append("    \"pass\": ").append(pass).append(",\n");
        json.append("    \"fail\": ").append(fail).append(",\n");
        json.append("    \"error\": ").append(error).append("\n");
        json.append("  },\n");
        json.append("  \"results\": [\n");

        for (int i = 0; i < results.size(); i++) {
            Map<String, String> r = results.get(i);

            json.append("    {\n");
            json.append("      \"ruleId\": \"").append(r.get("ruleId")).append("\",\n");
            json.append("      \"status\": \"").append(r.get("status")).append("\",\n");
            json.append("      \"line\": ").append(r.get("line")).append("\n");
            json.append("    }");

            if (i < results.size() - 1) json.append(",");
            json.append("\n");
        }

        json.append("  ]\n");
        json.append("}");

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(json.toString());
        }
    }
}
