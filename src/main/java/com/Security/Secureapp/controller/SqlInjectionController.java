package com.Security.Secureapp.controller;

import com.Security.Secureapp.model.User;
import com.Security.Secureapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class SqlInjectionController {

    @Autowired
    private UserService userService;

    // --- Vulnerable Endpoints (for demonstration) ---
    @GetMapping("/sql-vulnerable")
    public String showSqlSearchFormVulnerable(Model model) {
        model.addAttribute("title", "SQL Injection Vulnerable Search");
        model.addAttribute("description", "This search is vulnerable to SQL Injection using direct string concatenation.");
        model.addAttribute("actionUrl", "/sql-search-vulnerable");
        return "sql-search-form"; // Reusing the form with a different action
    }

    @PostMapping("/sql-search-vulnerable")
    public String searchUsersVulnerable(@RequestParam("username") String username, Model model) {
        System.out.println("-> /sql-search-vulnerable called with username: [" + username + "]");
        List<User> users;
        try {
            users = userService.findUserVulnerable(username);
            System.out.println("-> service returned " + users.size() + " users");
        } catch (Exception ex) {
            System.err.println("Exception in searchUsersVulnerable: " + ex.getMessage());
            ex.printStackTrace();
            model.addAttribute("title", "Error");
            model.addAttribute("message", "Server error: " + ex.getMessage());
            // It's good practice to provide a dedicated error page
            return "error";
        }

        model.addAttribute("users", users);
        model.addAttribute("query", username);
        model.addAttribute("title", "Vulnerable SQL Search Results");
        return "sql-search-results"; // Reusing results page
    }

    // --- Safe Endpoints (using JpaRepository methods) ---
    @GetMapping("/sql-safe-jpa")
    public String showSqlSearchFormSafeJpa(Model model) {
        model.addAttribute("title", "SQL Injection Safe Search (JpaRepository)");
        model.addAttribute("description", "This search uses Spring Data JPA (JpaRepository) methods, which automatically prevent SQL Injection.");
        model.addAttribute("actionUrl", "/sql-search-safe-jpa");
        return "sql-search-form"; // Reusing the form
    }

    @PostMapping("/sql-search-safe-jpa")
    public String searchUsersSafeJpa(@RequestParam("username") String username, Model model) {
        System.out.println("-> /sql-search-safe-jpa called with username: [" + username + "]");
        List<User> users;
        try {
            users = userService.findUserByUsernameJpa(username);
            System.out.println("-> service returned " + users.size() + " users");
        } catch (Exception ex) {
            System.err.println("Exception in searchUsersSafeJpa: " + ex.getMessage());
            ex.printStackTrace();
            model.addAttribute("title", "Error");
            model.addAttribute("message", "Server error: " + ex.getMessage());
            return "error";
        }

        model.addAttribute("users", users);
        model.addAttribute("query", username);
        model.addAttribute("title", "Safe JPA Search Results");
        return "sql-search-results";
    }

    // --- Safe Endpoints (using HQL) ---
    @GetMapping("/sql-safe-hql")
    public String showSqlSearchFormSafeHql(Model model) {
        model.addAttribute("title", "SQL Injection Safe Search (HQL)");
        model.addAttribute("description", "This search uses Hibernate Query Language (HQL) with named parameters, preventing SQL Injection.");
        model.addAttribute("actionUrl", "/sql-search-safe-hql");
        return "sql-search-form"; // Reusing the form
    }

    @PostMapping("/sql-search-safe-hql")
    public String searchUsersSafeHql(@RequestParam("username") String username, Model model) {
        System.out.println("-> /sql-search-safe-hql called with username: [" + username + "]");
        List<User> users;
        try {
            users = userService.findUserByUsernameHQL(username);
            System.out.println("-> service returned " + users.size() + " users");
        } catch (Exception ex) {
            System.err.println("Exception in searchUsersSafeHQL: " + ex.getMessage());
            ex.printStackTrace();
            model.addAttribute("title", "Error");
            model.addAttribute("message", "Server error: " + ex.getMessage());
            return "error";
        }

        model.addAttribute("users", users);
        model.addAttribute("query", username);
        model.addAttribute("title", "Safe HQL Search Results");
        return "sql-search-results";
    }

    // --- Safe Endpoints (using Stored Procedure) ---
    @GetMapping("/sql-safe-sp")
    public String showSqlSearchFormSafeSp(Model model) {
        model.addAttribute("title", "SQL Injection Safe Search (Stored Procedure)");
        model.addAttribute("description", "This search uses a database stored procedure with parameters, preventing SQL Injection.");
        model.addAttribute("actionUrl", "/sql-search-safe-sp");
        return "sql-search-form"; // Reusing the form
    }

    @PostMapping("/sql-search-safe-sp")
    public String searchUsersSafeSp(@RequestParam("username") String username, Model model) {
        System.out.println("-> /sql-search-safe-sp called with username: [" + username + "]");
        List<User> users;
        try {
            users = userService.findUserByStoredProcedure(username);
            System.out.println("-> service returned " + users.size() + " users");
        } catch (Exception ex) {
            System.err.println("Exception in searchUsersSafeSp: " + ex.getMessage());
            ex.printStackTrace();
            model.addAttribute("title", "Error");
            model.addAttribute("message", "Server error: " + ex.getMessage());
            return "error";
        }

        model.addAttribute("users", users);
        model.addAttribute("query", username);
        model.addAttribute("title", "Safe Stored Procedure Search Results");
        return "sql-search-results";
    }
}