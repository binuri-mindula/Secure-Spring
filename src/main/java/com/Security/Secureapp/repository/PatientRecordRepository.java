package com.Security.Secureapp.repository;

import com.Security.Secureapp.model.PatientRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PatientRecordRepository extends JpaRepository<PatientRecord, Long> {
    List<PatientRecord> findByAgeAndCityAndBloodType(int age, String city, String bloodType);
    List<PatientRecord> findByCityAndDiagnosis(String city, String diagnosis); // To set up "sensitive" data
}