package com.Security.Secureapp.controller;

import com.Security.Secureapp.model.PatientRecord;
import com.Security.Secureapp.service.PatientService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes; // For flash attributes

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class DataAggregationController {
    @Autowired
    private PatientService patientService;

    // Basic in-memory rate limiting to demonstrate the concept
    private final Map<String, LocalDateTime> lastQueryTime = new HashMap<>();
    private static final long QUERY_COOLDOWN_SECONDS = 5; // Example: 5 seconds cooldown per IP/session

    // Initialize some data for demonstration
    @PostConstruct
    public void initData() {
        if (patientService.searchPatients(30, "Sydney", "A+").isEmpty()) {
            // Note: We might need more data to make MIN_ANONYMOUS_GROUP_SIZE effective
            patientService.savePatient(new PatientRecord(null, "John Doe", 30, "Flu", "Sydney", "A+")); // Group 1
            patientService.savePatient(new PatientRecord(null, "Jane Smith", 30, "Diabetes", "Melbourne", "B-")); // Group 2
            patientService.savePatient(new PatientRecord(null, "Peter Jones", 45, "Flu", "Sydney", "O+")); // Group 3
            patientService.savePatient(new PatientRecord(null, "Alice Green", 30, "COVID-19", "Sydney", "A+")); // Group 1
            patientService.savePatient(new PatientRecord(null, "Bob White", 30, "Allergy", "Sydney", "A+")); // Group 1 - Added to ensure group size > 2 for testing
            patientService.savePatient(new PatientRecord(null, "Charlie Brown", 30, "Flu", "Sydney", "O+")); // Group 3 - Added
            patientService.savePatient(new PatientRecord(null, "David Lee", 45, "Cold", "Melbourne", "B-")); // Group 2 - Added
        }
    }

    @GetMapping("/data-aggregation-safe") // Renamed path to signify "safe" version
    public String showAggregationSearchForm(Model model) {
        return "data-aggregation-form-safe"; // New form name
    }

    @PostMapping("/data-aggregation-search-safe") // Renamed path to signify "safe" version
    public String searchForAggregation(@RequestParam(value = "age", required = false) Integer age,
                                       @RequestParam(value = "city", required = false) String city,
                                       @RequestParam(value = "bloodType", required = false) String bloodType,
                                       Model model,
                                       RedirectAttributes redirectAttributes) { // Added RedirectAttributes for messages

        // --- Rate Limiting (conceptual) ---
        // In a real app, you'd use Spring Security's rate limiting, or an external service.
        // This is a simplified, in-memory demo for a single session.
        String sessionId = "user_session_id"; // Replace with actual session/user ID or IP
        LocalDateTime now = LocalDateTime.now();
        if (lastQueryTime.containsKey(sessionId) &&
                lastQueryTime.get(sessionId).plusSeconds(QUERY_COOLDOWN_SECONDS).isAfter(now)) {
            redirectAttributes.addFlashAttribute("message", "Please wait before making another query.");
            return "redirect:/data-aggregation-safe";
        }
        lastQueryTime.put(sessionId, now);
        // --- End Rate Limiting ---


        if (age == null || city == null || bloodType == null || city.isEmpty() || bloodType.isEmpty()) {
            redirectAttributes.addFlashAttribute("message", "Please provide age, city, and blood type for search.");
            return "redirect:/data-aggregation-safe";
        }

        List<PatientRecord> results = patientService.searchPatients(age, city, bloodType);

        if (results.isEmpty()) {
            // This now also covers cases where the group size was too small
            model.addAttribute("message", "No matching records found, or the group is too small to display results due to privacy restrictions.");
            model.addAttribute("resultCount", 0); // Explicitly set to 0
        } else {
            model.addAttribute("resultCount", results.size());
        }

        model.addAttribute("queryAge", age);
        model.addAttribute("queryCity", city);
        model.addAttribute("queryBloodType", bloodType);
        return "data-aggregation-results-safe"; // New results page name
    }
}