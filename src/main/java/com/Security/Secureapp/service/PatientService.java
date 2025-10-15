package com.Security.Secureapp.service;

import com.Security.Secureapp.model.PatientRecord;
import com.Security.Secureapp.repository.PatientRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PatientService {
    @Autowired
    private PatientRecordRepository patientRecordRepository;

    // Define a minimum group size to prevent inference attacks.
    // If a query returns fewer than this many results, we won't reveal the exact count.
    private static final int MIN_ANONYMOUS_GROUP_SIZE = 3; // Example: Minimum 3 patients in a group

    public List<PatientRecord> searchPatients(int age, String city, String bloodType) {
        // !!! PREVENTED: Data Aggregation with Minimum Group Size Enforcement !!!
        List<PatientRecord> results = patientRecordRepository.findByAgeAndCityAndBloodType(age, city, bloodType);

        if (results.size() < MIN_ANONYMOUS_GROUP_SIZE) {
            // If the group is too small, return an empty list or throw an exception
            // to prevent revealing information about individuals.
            // In a real application, you might return a specific error code or a generic message.
            return List.of(); // Return empty list to signify "not enough data to display"
        }
        return results;
    }

    // For initial data setup
    public void savePatient(PatientRecord record) {
        patientRecordRepository.save(record);
    }
}