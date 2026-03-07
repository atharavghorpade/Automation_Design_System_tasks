package org.example.artifact;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ArtifactManager {

    public static void generateArtifactsFromJS(
            String jsDirectory,
            String benchmarkType) {

                
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

                String artifactDirPath =
                        "output/artifacts/" +
                        benchmarkType +
                        "/checks";

                Path artifactDir = Paths.get(artifactDirPath);

                if (!Files.exists(artifactDir)) {
                    Files.createDirectories(artifactDir);
                }

                Path outputFile =
                        artifactDir.resolve(jsFile.getName());

                Files.writeString(outputFile, jsContent);

                System.out.println(
                        "Artifact created → " +
                        outputFile.toAbsolutePath());
            }

        } catch (Exception e) {
            System.out.println("Artifact generation failed");
            e.printStackTrace();
        }
    }
}