# Secure Spring
The application is a small Spring MVC web application (Spring Boot) with a simple user management and 
prevention for vulnerabilities. Key features: 
1. User registration & login 
2. Roles: Admin, User, Viewer 
3. Simple CRUD for a User entity  
4. File upload endpoint and document upload
5. Prevention for
   - Cross-Site Scripting (XSS) Attack,
   - SQL injection Attack,
   - Unrestricted Upload of a file
   - Cross-Site Request Forgery (CSRF)
   - Data aggregation attack (inference issue)
   - Server-Side Request Forgery (SSRF)
Technology stack: 
• Java 17 
• Spring Boot (Spring MVC, Spring Data JPA / Hibernate) 
• Thymeleaf templates 
• MySQL (development DB) 
• Maven 
• SonarQube (local Sonar server) for SAST 
• OWASP ZAP for DAST
