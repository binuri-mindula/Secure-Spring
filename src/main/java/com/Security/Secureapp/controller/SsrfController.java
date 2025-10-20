package com.Security.Secureapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.net.URI;
import java.net.URISyntaxException;

@Controller
public class SsrfController {

    // Define a whitelist of allowed hostnames or specific URLs
    // This should ideally be loaded from a configuration file or database.
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "example.com",
            "api.partner.com",
            "localhost" // Only allow if explicitly needed for internal services, be cautious!
    ));

    // Optional: Whitelist specific full URLs if that's more appropriate for your use case
    private static final Set<String> ALLOWED_FULL_URLS = new HashSet<>(Arrays.asList(
            "http://localhost:8080/internal_data.txt",
            "https://www.example.com/some/public/data.json"
    ));


   @GetMapping("/ssrf-vulnerable") // Keep the vulnerable one for comparison/demo if needed, or rename
    public String showSsrfFormVulnerable() {
        return "ssrf-form"; // This form will now point to the safe endpoint
    }

    @GetMapping("/ssrf-safe") // A new endpoint for the safe form if you want separate forms
    public String showSsrfFormSafe() {
        return "ssrf-form-safe"; // You'd need a new ssrf-form-safe.html for this
    }

    @PostMapping("/ssrf-read-file") // This endpoint will now be secured
    public String readFileSafe(@RequestParam("fileUrl") String fileUrl, Model model) {
        StringBuilder content = new StringBuilder();
        try {
            // --- 1. Input Validation: Basic URL format and scheme checks ---
            URL url;
            try {
                url = new URL(fileUrl);
            } catch (MalformedURLException e) {
                model.addAttribute("error", "Invalid URL format provided.");
                return "ssrf-display";
            }

            // Ensure only HTTP/HTTPS schemes are allowed
            String protocol = url.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                model.addAttribute("error", "Only HTTP and HTTPS protocols are allowed.");
                return "ssrf-display";
            }

            // --- 2. URL Whitelisting: Check against allowed hosts/full URLs ---
            String host = url.getHost();
            // Important: Resolve the IP address of the host to prevent DNS rebinding attacks
            // For a robust solution, you might want to resolve the IP and check against a whitelist of allowed IPs/CIDRs
            // For simplicity here, we're checking hostname directly, but be aware of DNS rebinding.
            // A more advanced check would involve:
            // InetAddress address = InetAddress.getByName(host);
            // String ip = address.getHostAddress();
            // if (!isAllowedIp(ip)) { ... } // where isAllowedIp checks against a range of trusted IPs

            boolean isHostWhitelisted = ALLOWED_HOSTS.contains(host);
            boolean isFullUrlWhitelisted = ALLOWED_FULL_URLS.contains(fileUrl);

            // You can combine these as per your policy:
            // - Only allow whitelisted hosts for any path
            // - Only allow specific full URLs
            // - Allow whitelisted hosts BUT only for specific paths/prefixes (more complex logic needed)
            if (!isHostWhitelisted && !isFullUrlWhitelisted) {
                model.addAttribute("error", "Access to the requested URL is not permitted (Host/URL not whitelisted).");
                return "ssrf-display";
            }

            // Optional: Prevent access to private IP ranges (Blacklisting) as an extra layer
            // This is harder to do perfectly and can be bypassed, whitelisting is stronger.
            // Example of a basic check, but a full solution needs more robust IP parsing.
            try {
                URI uri = new URI(fileUrl); // Use URI for better parsing of components
                if (uri.getHost() != null) {
                    java.net.InetAddress addr = java.net.InetAddress.getByName(uri.getHost());
                    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) {
                        // This checks for localhost (127.0.0.1) and private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
                        // If 'localhost' is explicitly whitelisted above, this check might need adjustment or should come before.
                        if (!ALLOWED_HOSTS.contains(host)) { // Only block if localhost wasn't explicitly allowed
                            model.addAttribute("error", "Access to private network resources is not allowed.");
                            return "ssrf-display";
                        }
                    }
                }
            } catch (URISyntaxException | java.net.UnknownHostException e) {
                // Ignore, URL validation already handled malformed URLs
            }


            // If all checks pass, proceed to read
            try (BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()))) {
                String line;
                while ((line = in.readLine()) != null) {
                    content.append(line).append("\n");
                }
            }
            model.addAttribute("fileContent", content.toString());
        } catch (Exception e) {
            // Log the full exception for debugging, but provide a generic error to the user
            System.err.println("SSRF Read Error: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "An error occurred while trying to retrieve content.");
        }
        return "ssrf-display";
    }
}