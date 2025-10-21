package com.Security.Secureapp.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class SecurityDemoController {

    private static final Logger logger = LoggerFactory.getLogger(SecurityDemoController.class);

    // Simple in-memory "profile" for demonstration (shared, but only modified via secured endpoints)
    private String sharedUserEmail = "shared@example.com";
    private String sharedUserProfileName = "Shared User";

    // --- Authentication & Authorization Demos ---
    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "logout", required = false) String logout,
                        Model model) {
        if (error != null) {
            model.addAttribute("error", "Invalid username or password.");
        }
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", authentication.getName());
        model.addAttribute("roles", authentication.getAuthorities());
        return "dashboard";
    }

    @GetMapping("/user/dashboard")
    public String userDashboard(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", authentication.getName());
        model.addAttribute("message", "Welcome to the User Dashboard!");
        logger.info("Access granted to /user/dashboard for user: {}", authentication.getName());
        return "user-dashboard";
    }

    @GetMapping("/admin/panel")
    public String adminPanel(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", authentication.getName());
        model.addAttribute("message", "Welcome to the Admin Panel!");
        logger.info("Access granted to /admin/panel for admin: {}", authentication.getName());
        return "admin-panel";
    }

    @GetMapping("/viewer/page")
    public String viewerPage(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", authentication.getName());
        model.addAttribute("message", "Welcome to the Viewer Page!");
        logger.info("Access granted to /viewer/page for user: {}", authentication.getName());
        return "viewer-page";
    }

    // --- Profile Management with Spring Security's Default CSRF Protection ---

    @GetMapping("/profile-protected-spring")
    public String showProfileProtectedSpring(Model model) {
        model.addAttribute("email", sharedUserEmail);
        model.addAttribute("profileName", sharedUserProfileName);
        // Spring Security automatically adds the _csrf token to the model for Thymeleaf forms
        // No manual token generation or addition needed here.
        return "profile-settings-protected-spring";
    }

    @PostMapping("/update-email-protected-spring")
    public String updateEmailProtectedSpring(
            @RequestParam("newEmail") String newEmail,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request) { // Request to show _csrf details

        // Spring Security's CsrfFilter automatically validates the _csrf token
        // and throws an AccessDeniedException if it's invalid/missing.
        // We don't need manual validation here.

        this.sharedUserEmail = newEmail;
        redirectAttributes.addFlashAttribute("message", "Email updated successfully to: " + newEmail + " (Spring Security CSRF Protected)");
        logger.info("Email updated via Spring Security protected endpoint by user: {}", SecurityContextHolder.getContext().getAuthentication().getName());
        return "redirect:/profile-protected-spring";
    }

    @PostMapping("/update-profile-name-protected-spring")
    public String updateProfileNameProtectedSpring(
            @RequestParam("newName") String newName,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request) {

        // Spring Security's CsrfFilter automatically validates the _csrf token
        // and throws an AccessDeniedException if it's invalid/missing.
        // We don't need manual validation here.

        this.sharedUserProfileName = newName;
        redirectAttributes.addFlashAttribute("message", "Profile name updated successfully to: " + newName + " (Spring Security CSRF Protected)");
        logger.info("Profile name updated via Spring Security protected endpoint by user: {}", SecurityContextHolder.getContext().getAuthentication().getName());
        return "redirect:/profile-protected-spring";
    }

    // You can keep the existing CsrfController.java for the custom CSRF demo
    // but ensure it uses different mapping paths or is otherwise distinct.
    // For this example, I'll assume you want both to co-exist for demonstration.
    // The previous CsrfController remains as is for the custom implementation.
}