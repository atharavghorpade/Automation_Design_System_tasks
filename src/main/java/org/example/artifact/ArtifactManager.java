package org.example.artifact;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ArtifactManager {

    public static void generateArtifactsFromJS(String jsDirectory, String benchmarkType) {

        try {

            File folder = new File(jsDirectory);

            if (!folder.exists()) {
                System.out.println("JS directory not found: " + jsDirectory);
                return;
            }

            File[] jsFiles = folder.listFiles((dir, name) -> name.endsWith(".js"));

            if (jsFiles == null || jsFiles.length == 0) {
                System.out.println("No JS files found in: " + jsDirectory);
                return;
            }

            for (File jsFile : jsFiles) {

                String jsContent = Files.readString(jsFile.toPath());

                String ruleName = jsFile.getName().replace(".js", "");

                Path ruleFolder = Paths.get(
                        "output/artifacts/" + benchmarkType + "/checks/" + ruleName
                );

                if (!Files.exists(ruleFolder)) {
                    Files.createDirectories(ruleFolder);
                }

                int latestVersion = getLatestVersion(ruleFolder.toFile(), ruleName);

                // Compare with latest version
                if (latestVersion > 0) {

                    Path latestFile =
                            ruleFolder.resolve(ruleName + "_v" + latestVersion + ".js");

                    String existingContent = Files.readString(latestFile);

                    if (existingContent.equals(jsContent)) {
                        System.out.println(
                                "No change detected for " + ruleName +
                                ". Skipping new artifact."
                        );
                        continue;
                    }
                }

                int newVersion = latestVersion + 1;

                Path outputFile =
                        ruleFolder.resolve(ruleName + "_v" + newVersion + ".js");

                Files.writeString(outputFile, jsContent);

                System.out.println(
                        "Artifact created → " + outputFile.toAbsolutePath());
            }

        } catch (Exception e) {

            System.out.println("Artifact generation failed");
            e.printStackTrace();
        }
    }

    private static int getLatestVersion(File folder, String ruleName) {

        int maxVersion = 0;

        File[] files = folder.listFiles();

        if (files != null) {

            for (File file : files) {

                String name = file.getName();

                if (name.startsWith(ruleName + "_v") && name.endsWith(".js")) {

                    try {

                        String versionPart =
                                name.substring(
                                        name.indexOf("_v") + 2,
                                        name.lastIndexOf(".")
                                );

                        int version = Integer.parseInt(versionPart);

                        if (version > maxVersion) {
                            maxVersion = version;
                        }

                    } catch (Exception ignored) {}
                }
            }
        }

        return maxVersion;
    }
}