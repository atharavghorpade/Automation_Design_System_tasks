package org.example;

import java.io.File;
import java.util.List;

import org.example.Extractor.CISMetadataExtractor;
import org.example.Extractor.STIGMetadataExtractor;
import org.example.Generator.CIS_checkGenerator;
import org.example.Generator.JsonFileGenerator;
import org.example.Generator.STIG_checkGenerator;
import org.example.artifact.ArtifactManager; // New import for artifact generation
import org.example.model.CIS_Benchmark;
import org.example.model.STIG_Benchmark;
import org.example.runner.JSValidationRunner; 

public class Main {  

    public static void main(String[] args) {

        try {

            File cisFile = PdfLoader.getPdfFileIfExists("input/cis"); // Assuming this method checks for the existence of a PDF file in the specified directory and returns it if found.
            File stigFile = PdfLoader.getPdfFileIfExists("input/stig"); // Same as above but for the STIG directory.

            if (cisFile != null) {

                System.out.println("Processing CIS: " + cisFile.getName());

                CISMetadataExtractor cisExtractor = new CISMetadataExtractor();
                List<CIS_Benchmark> cisList = cisExtractor.extract(cisFile);
                System.out.println("Total CIS Rules Extracted: " + cisList.size());

                JsonFileGenerator.generateJson(cisList, "cis-metadata.json");
                CIS_checkGenerator.generateChecks(cisList);
            }

            if (stigFile != null) {

                System.out.println("Processing STIG: " + stigFile.getName());

                STIGMetadataExtractor stigExtractor = new STIGMetadataExtractor();
                List<STIG_Benchmark> stigList = stigExtractor.extract(stigFile);
                System.out.println("Total STIG Rules Extracted: " + stigList.size());

                JsonFileGenerator.generateJson(stigList, "stig-metadata.json");
                STIG_checkGenerator.generateChecks(stigList);
            }

            if (cisFile == null && stigFile == null) {
                System.out.println("No input PDFs found. System exiting.");
            }

            JSValidationRunner.runValidation();

            System.out.println("Validation Completed Successfully.");

            // Artifact generation (added)
            ArtifactManager.generateArtifactsFromJS(
                    "output/generatedJS/cis-checks",
                    "cis");

            ArtifactManager.generateArtifactsFromJS(
                    "output/generatedJS/stig-checks",
                    "stig");

            System.out.println("Artifact generation completed.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
//end of main