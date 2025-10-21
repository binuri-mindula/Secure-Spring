package com.Security.Secureapp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class XssInputDto {
    @NotBlank(message = "Message must not be blank")
    @Size(max = 1000, message = "Message must be at most 1000 characters")
    private String userInput;

    public XssInputDto() {}

    public XssInputDto(String userInput) {
        this.userInput = userInput;
    }

    public String getUserInput() {
        return userInput;
    }
    public void setUserInput(String userInput) {
        this.userInput = userInput;
    }
}
