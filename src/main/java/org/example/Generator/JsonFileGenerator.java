package org.example.Generator;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.example.ProjectPaths;

public class JsonFileGenerator {

    private static final String SCHEMA_VERSION = "1.0";

    public static <T> void generateJson(List<T> data, String fileName) throws Exception {

        // Validate data
        if (data == null || data.isEmpty()) {  // Added null check for data list
            throw new IllegalArgumentException("Metadata list cannot be null or empty.");
        }

        // Create output folder if not exists
        Path outputPath = Paths.get(ProjectPaths.METADATA_DIR);
        if (!Files.exists(outputPath)) {
            Files.createDirectories(outputPath);
        }

        File outputFile = outputPath.resolve(fileName).toFile();

        // Create standardized wrapper
        Map<String, Object> standardizedOutput = new HashMap<>();
        standardizedOutput.put("schemaVersion", SCHEMA_VERSION);
        standardizedOutput.put("generatedAt", LocalDate.now().toString());
        standardizedOutput.put("totalRules", data.size());
        standardizedOutput.put("rules", data);

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        mapper.writeValue(outputFile, standardizedOutput);
    }
}
