package com.Security.Secureapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Collections;
import java.util.List;

@Controller
@RequestMapping("/") // Base path for this controller
public class HomeController {

    @GetMapping
    public String home(Model model) {
        // You can add attributes to the model here if needed for the home page
        model.addAttribute("message", "Welcome to SecureApp!");
        return "home"; // This refers to home.html in src/main/resources/templates
    }


}