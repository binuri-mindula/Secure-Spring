package com.Security.Secureapp.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import java.util.UUID; // For generating unique filenames

@Controller
public class FileUploadController {


    private final Path SAFE_UPLOAD_DIR = Paths.get("target/uploads-safe").toAbsolutePath().normalize();
    private final Path VULNERABLE_UPLOAD_DIR = Paths.get("src/main/resources/static/uploads-vulnerable").toAbsolutePath().normalize();

    // Whitelist of allowed extensions
    private final List<String> ALLOWED_EXTENSIONS = Arrays.asList("jpg", "jpeg", "png", "gif", "pdf", "txt");
    private final List<String> ALLOWED_IMAGE_MIME_TYPES = Arrays.asList("image/jpeg", "image/png", "image/gif");
    private final long MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

    public FileUploadController() {
        try {
            Files.createDirectories(VULNERABLE_UPLOAD_DIR);
            System.out.println("Vulnerable upload directory created: " + VULNERABLE_UPLOAD_DIR);
            Files.createDirectories(SAFE_UPLOAD_DIR);
            System.out.println("Safe upload directory created: " + SAFE_UPLOAD_DIR);
        } catch (IOException e) {
            System.err.println("Failed to create upload directories: " + e.getMessage());
            // In a real app, handle this more robustly, possibly by exiting or logging severe error
        }
    }

    // --- Vulnerable Endpoints (for demonstration) ---
    @GetMapping("/upload-vulnerable")
    public String showVulnerableUploadForm(Model model) {
        model.addAttribute("title", "Vulnerable File Upload");
        model.addAttribute("actionUrl", "/upload-file-vulnerable");
        model.addAttribute("warning", "This upload is highly insecure. Do not use in production!");
        return "upload-form";
    }

    @PostMapping("/upload-file-vulnerable")
    public String uploadFileVulnerable(@RequestParam("file") MultipartFile file,
                                       RedirectAttributes redirectAttributes) {

        if (file.isEmpty()) {
            redirectAttributes.addFlashAttribute("message", "Please select a file to upload.");
            redirectAttributes.addFlashAttribute("isError", true);
            return "redirect:/upload-status";
        }

        try {


            String originalFilename = file.getOriginalFilename();
            // Basic path traversal protection (not full prevention, just stripping path)
            String safeFilename = Paths.get(originalFilename).getFileName().toString(); // STILL VULNERABLE TO .jsp.txt, double extensions, etc.

            Path destinationPath = VULNERABLE_UPLOAD_DIR.resolve(safeFilename);
            Files.copy(file.getInputStream(), destinationPath, StandardCopyOption.REPLACE_EXISTING);

            redirectAttributes.addFlashAttribute("message", "File uploaded successfully (VULNERABLE): " + safeFilename);
            redirectAttributes.addFlashAttribute("filePath", "/uploads-vulnerable/" + safeFilename); // Public URL
            redirectAttributes.addFlashAttribute("isError", false);

        } catch (IOException e) {
            System.err.println("Vulnerable file upload failed: " + e.getMessage());
            e.printStackTrace();
            redirectAttributes.addFlashAttribute("message", "Failed to upload file (VULNERABLE): " + e.getMessage());
            redirectAttributes.addFlashAttribute("isError", true);
        }
        return "redirect:/upload-status";
    }

    // --- Safe Endpoints (with prevention mechanisms) ---
    @GetMapping("/upload-safe")
    public String showSafeUploadForm(Model model) {
        model.addAttribute("title", "Secure File Upload");
        model.addAttribute("actionUrl", "/upload-file-safe");
        model.addAttribute("info", "This upload implements multiple security checks.");
        return "upload-form";
    }

    @PostMapping("/upload-file-safe")
    public String uploadFileSafe(@RequestParam("file") MultipartFile file,
                                 RedirectAttributes redirectAttributes) {

        if (file.isEmpty()) {
            redirectAttributes.addFlashAttribute("message", "Please select a file to upload.");
            redirectAttributes.addFlashAttribute("isError", true);
            return "redirect:/upload-status";
        }

        // 1. File Size Validation
        if (file.getSize() > MAX_FILE_SIZE_BYTES) {
            redirectAttributes.addFlashAttribute("message", "File size exceeds the limit of " + (MAX_FILE_SIZE_BYTES / (1024 * 1024)) + " MB.");
            redirectAttributes.addFlashAttribute("isError", true);
            return "redirect:/upload-status";
        }

        String originalFilename = file.getOriginalFilename();
        String fileExtension = getFileExtension(originalFilename);

        // 2. Strict File Extension Whitelist Validation
        if (fileExtension.isEmpty() || !ALLOWED_EXTENSIONS.contains(fileExtension.toLowerCase())) {
            redirectAttributes.addFlashAttribute("message", "Invalid file type. Only " + String.join(", ", ALLOWED_EXTENSIONS) + " are allowed.");
            redirectAttributes.addFlashAttribute("isError", true);
            return "redirect:/upload-status";
        }

        // 3. MIME Type Validation (can be faked, but adds a layer)
        String contentType = file.getContentType();
        if (contentType == null || (!ALLOWED_IMAGE_MIME_TYPES.contains(contentType) && (fileExtension.equalsIgnoreCase("jpg") || fileExtension.equalsIgnoreCase("png") || fileExtension.equalsIgnoreCase("gif")))) {
            // If it's an image extension but not a valid image MIME type, or if content type is null
            redirectAttributes.addFlashAttribute("message", "Invalid MIME type for the selected file.");
            redirectAttributes.addFlashAttribute("isError", true);
            return "redirect:/upload-status";
        }

        try {
            // 4. Content Analysis (e.g., for images, try to read as an image)
            if (ALLOWED_IMAGE_MIME_TYPES.contains(contentType)) {
                try (var inputStream = file.getInputStream()) {
                    BufferedImage image = ImageIO.read(inputStream);
                    if (image == null) {
                        redirectAttributes.addFlashAttribute("message", "The uploaded file is not a valid image.");
                        redirectAttributes.addFlashAttribute("isError", true);
                        return "redirect:/upload-status";
                    }
                }

            }

            // 5. Secure Filename Generation (UUID)
            String uniqueFilename = UUID.randomUUID().toString() + "." + fileExtension.toLowerCase();
            Path destinationPath = SAFE_UPLOAD_DIR.resolve(uniqueFilename);

            // 6. Store Outside Web Root (SAFE_UPLOAD_DIR is configured outside static/)
            Files.copy(file.getInputStream(), destinationPath, StandardCopyOption.REPLACE_EXISTING);

            redirectAttributes.addFlashAttribute("message", "File uploaded securely: " + originalFilename + " (saved as " + uniqueFilename + ")");

            redirectAttributes.addFlashAttribute("filePath", "/download-safe/" + uniqueFilename); // Provide an app-controlled download link
            redirectAttributes.addFlashAttribute("isError", false);

        } catch (IOException e) {
            System.err.println("Secure file upload failed: " + e.getMessage());
            e.printStackTrace();
            redirectAttributes.addFlashAttribute("message", "Failed to upload file securely: " + e.getMessage());
            redirectAttributes.addFlashAttribute("isError", true);
        }
        return "redirect:/upload-status";
    }

    // Endpoint to securely serve uploaded files (for files stored outside web root)
    @GetMapping("/download-safe/{filename}")
    public void downloadSafeFile(@PathVariable String filename, HttpServletResponse response) {
        Path filePath = SAFE_UPLOAD_DIR.resolve(filename);

        if (!Files.exists(filePath)) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        // Basic validation: ensure filename looks like a UUID-generated name
        // This is important to prevent path traversal when resolving from SAFE_UPLOAD_DIR
        if (!filename.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\.(jpg|jpeg|png|gif|pdf|txt)$")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST); // Invalid filename format
            return;
        }


        try {
            String mimeType = Files.probeContentType(filePath);
            if (mimeType == null) {
                mimeType = "application/octet-stream"; // Default if type not detectable
            }

            // Set appropriate headers for file download
            response.setContentType(mimeType);
            response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\""); // Force download
            response.setHeader("Content-Length", String.valueOf(Files.size(filePath)));

            Files.copy(filePath, response.getOutputStream());
            response.flushBuffer();
        } catch (IOException ex) {
            System.err.println("Error serving file: " + ex.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }


    // Displays the upload status page after redirect
    @GetMapping("/upload-status")
    public String uploadStatus(Model model) {
        // RedirectAttributes automatically add flash attributes to the model for the redirected request
        model.addAttribute("title", "Upload Status");
        return "upload-status";
    }

    private String getFileExtension(String filename) {
        if (filename == null || filename.lastIndexOf('.') == -1) {
            return "";
        }
        return filename.substring(filename.lastIndexOf('.') + 1);
    }
}