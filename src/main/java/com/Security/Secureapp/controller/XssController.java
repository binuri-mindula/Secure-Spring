package com.Security.Secureapp.controller;

import com.Security.Secureapp.model.XssForm;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class XssController {

    @GetMapping("/xss-safe-form")
    public String showXssForm(Model model) {
        model.addAttribute("title", "XSS Prevention Form");
        model.addAttribute("description", "Enter any message. This form prevents XSS through server-side validation and proper output encoding.");
        model.addAttribute("xssForm", new XssForm()); // Bind empty form object
        return "xss-safe-form"; // Thymeleaf template
    }

    @PostMapping("/xss-safe-submit")
    public String submitXssSafe(
            @Valid XssForm xssForm, // Validate the form object
            BindingResult bindingResult, // Must come immediately after @Valid object
            Model model,
            RedirectAttributes redirectAttributes) {

        // Check for validation errors
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    bindingResult.getFieldError("userInput").getDefaultMessage());
            return "redirect:/xss-safe-form";
        }

        // Add escaped message to the model
        model.addAttribute("displayMessage", xssForm.getUserInput());
        model.addAttribute("title", "XSS Prevention Result");
        model.addAttribute("infoMessage", "Notice how any HTML/JavaScript you entered is now displayed as plain text, not executed!");
        return "xss-display-safe"; // Result page
    }
}
