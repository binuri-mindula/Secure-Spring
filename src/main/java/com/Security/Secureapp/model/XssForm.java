package com.Security.Secureapp.model;

import jakarta.validation.constraints.NotBlank;

public class XssForm {

    @NotBlank(message = "Input cannot be empty!")
    private String userInput;

    // Getter and Setter
    public String getUserInput() {
        return userInput;
    }

    public void setUserInput(String userInput) {
        this.userInput = userInput;
    }
}

