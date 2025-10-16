package com.Security.Secureapp.controller;

import com.Security.Secureapp.exception.CsrfValidationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

@Controller
public class CsrfController {

    private static final Logger logger = LoggerFactory.getLogger(CsrfController.class);

    // Simple in-memory "profile" for demonstration
    private String userEmail = "test@example.com";
    private String userProfileName = "Default User";

    // *** FIX: Make CSRF_TOKEN_ATTR public ***
    public static final String CSRF_TOKEN_ATTR = "csrf_token";
    private static final String REFERER_HEADER = "Referer"; // Note: HTTP header name is 'Referer' (misspelled)

    // --- Helper method to generate and store CSRF token ---
    private String generateCsrfToken(HttpSession session) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        // Store in session combined with session ID for stronger binding (optional but good practice)
        session.setAttribute(CSRF_TOKEN_ATTR + "_" + session.getId(), token);
        logger.debug("Generated CSRF token for session {}: {}", session.getId(), token);
        return token;
    }

    // --- Helper method to validate CSRF token ---
    private void validateCsrfToken(String submittedToken, HttpSession session) {
        String expectedToken = (String) session.getAttribute(CSRF_TOKEN_ATTR + "_" + session.getId());
        if (submittedToken == null || expectedToken == null || !submittedToken.equals(expectedToken)) {
            logger.warn("CSRF token validation failed. Expected: {}, Submitted: {}", expectedToken, submittedToken);
            throw new CsrfValidationException("Invalid CSRF token. Request may be forged.");
        }
        // Token successfully used, remove it to enforce one-time usage or regenerate for subsequent requests
        // For simplicity, we'll regenerate on GET requests to display the form.
        session.removeAttribute(CSRF_TOKEN_ATTR + "_" + session.getId());
        logger.debug("CSRF token validated successfully for session {}", session.getId());
    }

    // --- Helper method to validate Referer header ---
    private void validateReferer(HttpServletRequest request) {
        String referer = request.getHeader(REFERER_HEADER);
        String requestHost = request.getServerName(); // e.g., "localhost" or "example.com"
        int requestPort = request.getServerPort();

        if (referer == null || !referer.contains(requestHost)) {
            logger.warn("Referer header validation failed. Referer: {}, Request Host: {}", referer, requestHost);
            throw new CsrfValidationException("Invalid or missing Referer header. Request may be forged.");
        }
        // More robust check for port and protocol could be added
        if (referer.contains(":" + requestPort) && referer.startsWith(request.getScheme() + "://")) {
            logger.debug("Referer header validated successfully: {}", referer);
        } else {
            logger.warn("Referer header protocol/port mismatch. Referer: {}, Expected: {}://{}:{}",
                    referer, request.getScheme(), requestHost, requestPort);
            // Depending on strictness, this could also throw an exception or be a warning
        }
    }


    @GetMapping("/profile") // Protected GET endpoint
    public String showProfileProtected(Model model, HttpSession session) {
        model.addAttribute("email", userEmail);
        model.addAttribute("profileName", userProfileName);
        model.addAttribute("csrfToken", generateCsrfToken(session)); // Generate and add token for forms
        return "profile-settings-protected"; // Use a new Thymeleaf template
    }

    @PostMapping("/update-email") // Protected POST endpoint
    public String updateEmailProtected(
            @RequestParam("newEmail") String newEmail,
            @RequestParam(CSRF_TOKEN_ATTR) String csrfToken, // Receive token from form
            HttpServletRequest request,
            HttpSession session,
            Model model,
            RedirectAttributes redirectAttributes) {

        // 1. Validate Referer Header
        validateReferer(request);

        // 2. Validate CSRF Token
        validateCsrfToken(csrfToken, session);

        this.userEmail = newEmail;
        redirectAttributes.addFlashAttribute("message", "Email updated successfully to: " + newEmail);
        return "redirect:/profile"; // Redirect to prevent double submission
    }

    @PostMapping("/update-profile-name") // Protected POST endpoint
    public String updateProfileNameProtected(
            @RequestParam("newName") String newName,
            @RequestParam(CSRF_TOKEN_ATTR) String csrfToken, // Receive token from form
            HttpServletRequest request,
            HttpSession session,
            Model model,
            RedirectAttributes redirectAttributes) {

        // 1. Validate Referer Header
        validateReferer(request);

        // 2. Validate CSRF Token
        validateCsrfToken(csrfToken, session);

        this.userProfileName = newName;
        redirectAttributes.addFlashAttribute("message", "Profile name updated successfully to: " + newName);
        return "redirect:/profile"; // Redirect to prevent double submission
    }

    // --- Controller-level Exception Handler for specific cases within this controller ---
    // Note: GlobalExceptionHandler will catch exceptions not handled here.
    @ExceptionHandler(CsrfValidationException.class)
    public ModelAndView handleCsrfExceptionsInController(HttpServletRequest request, CsrfValidationException ex) {
        logger.error("Controller-level CSRF Error: {} for URL: {}", ex.getMessage(), request.getRequestURL());
        ModelAndView mav = new ModelAndView("error"); // Renders error.html
        mav.addObject("status", 400); // Bad Request
        mav.addObject("error", "Invalid Request");
        mav.addObject("message", "Security Alert: " + ex.getMessage());
        mav.addObject("timestamp", new java.util.Date());
        mav.addObject("path", request.getRequestURI());
        return mav;
    }


    // --- Original Vulnerable Endpoints (for comparison) ---
    @GetMapping("/profile-vulnerable")
    public String showProfileVulnerable(Model model) {
        model.addAttribute("email", userEmail);
        model.addAttribute("profileName", userProfileName);
        return "profile-settings-vulnerable"; // Use the original template
    }

    @PostMapping("/update-email-vulnerable")
    public String updateEmailVulnerable(@RequestParam("newEmail") String newEmail, Model model) {
        // !!! VULNERABLE: No CSRF token validation !!!
        logger.warn("Vulnerable email update executed to: {}", newEmail);
        this.userEmail = newEmail;
        model.addAttribute("message", "Email updated successfully to: " + newEmail);
        model.addAttribute("email", userEmail);
        model.addAttribute("profileName", userProfileName);
        return "profile-settings-vulnerable";
    }

    @PostMapping("/update-profile-name-vulnerable")
    public String updateProfileNameVulnerable(@RequestParam("newName") String newName, Model model) {
        // !!! VULNERABLE: No CSRF token validation !!!
        logger.warn("Vulnerable profile name update executed to: {}", newName);
        this.userProfileName = newName;
        model.addAttribute("message", "Profile name updated successfully to: " + newName);
        model.addAttribute("email", userEmail);
        model.addAttribute("profileName", userProfileName);
        return "profile-settings-vulnerable";
    }
}