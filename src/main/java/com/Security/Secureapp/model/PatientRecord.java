package com.Security.Secureapp.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class PatientRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String patientName; // pseudonymized or fake for vulnerability demo
    private int age;
    private String diagnosis; // Sensitive
    private String city;
    private String bloodType; // Less sensitive

    // No-argument constructor
    public PatientRecord() { }

    // All-argument constructor
    public PatientRecord(Long id, String patientName, int age, String diagnosis, String city, String bloodType) {
        this.id = id;
        this.patientName = patientName;
        this.age = age;
        this.diagnosis = diagnosis;
        this.city = city;
        this.bloodType = bloodType;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPatientName() {
        return patientName;
    }

    public void setPatientName(String patientName) {
        this.patientName = patientName;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getDiagnosis() {
        return diagnosis;
    }

    public void setDiagnosis(String diagnosis) {
        this.diagnosis = diagnosis;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getBloodType() {
        return bloodType;
    }

    public void setBloodType(String bloodType) {
        this.bloodType = bloodType;
    }

    // Optional: toString() for debugging
    @Override
    public String toString() {
        return "PatientRecord{" +
                "id=" + id +
                ", patientName='" + patientName + '\'' +
                ", age=" + age +
                ", diagnosis='" + diagnosis + '\'' +
                ", city='" + city + '\'' +
                ", bloodType='" + bloodType + '\'' +
                '}';
    }
}
