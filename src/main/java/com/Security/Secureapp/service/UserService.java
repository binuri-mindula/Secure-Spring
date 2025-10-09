package com.Security.Secureapp.service;

import com.Security.Secureapp.model.User;
import com.Security.Secureapp.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import jakarta.persistence.StoredProcedureQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @PersistenceContext
    private EntityManager em;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    @Transactional
    public void init() {
        // ...
        if (userRepository.findByUsername("admin").isEmpty()) {
            userRepository.save(new User(null,"admin", passwordEncoder.encode("adminpass"),"ADMIN"));
        }
        if (userRepository.findByUsername("user").isEmpty()) {
            userRepository.save(new User(null,"user", passwordEncoder.encode("userpass"),"USER"));
        }
        if (userRepository.findByUsername("viewer").isEmpty()) {
            userRepository.save(new User(null,"viewer", passwordEncoder.encode("viewerpass"),"VIEWER"));
        }
        if (userRepository.findByUsername("dev").isEmpty()) {
            userRepository.save(new User(null,"dev", passwordEncoder.encode("devpass"),"DEVELOPER"));
        }
        System.out.println("Dummy users initialized");
    }

    // --- SQL Injection Vulnerable Method (for demonstration) ---
    @Transactional(readOnly = true)
    public List<User> findUserVulnerable(String username) {
        if (username == null) return Collections.emptyList();

        // !!! VULNERABLE: Direct string concatenation in a native SQL query !!!
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        System.out.println("VULNERABLE Query: " + sql); // For debugging to see the injected SQL
        Query query = em.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    // --- Prevention Mechanism 1: Using JpaRepository (Spring Data JPA) ---
    // This is the RECOMMENDED way for most CRUD operations.
    @Transactional(readOnly = true)
    public List<User> findUserByUsernameJpa(String username) {
        if (username == null) return Collections.emptyList();
        // Spring Data JPA's derived query methods automatically use prepared statements.
        return userRepository.findByUsername(username)
                .map(List::of)
                .orElseGet(Collections::emptyList);
    }

    // --- Prevention Mechanism 2: Using HQL (Hibernate Query Language) with Parameters ---
    @Transactional(readOnly = true)
    public List<User> findUserByUsernameHQL(String username) {
        if (username == null) return Collections.emptyList();

        // HQL uses named or positional parameters, which are safely bound by Hibernate.
        String hql = "FROM User u WHERE u.username = :username";
        return em.createQuery(hql, User.class)
                .setParameter("username", username) // Parameter binding prevents injection
                .getResultList();
    }

    // --- Prevention Mechanism 3: Using a SQL Stored Procedure with Parameters ---
    // NOTE: You need to create this stored procedure in your database first.
    // Example for MySQL:
    // DELIMITER $$
    // CREATE PROCEDURE find_users_by_username(IN p_username VARCHAR(255))
    // BEGIN
    //    SELECT id, username, password, role FROM users WHERE username = p_username;
    // END$$
    // DELIMITER ;
    // For H2 (in-memory, for easy testing):
    // CREATE ALIAS FIND_USERS_BY_USERNAME AS $$
    // import java.sql.*;
    // @CODE
    // ResultSet findUsers(Connection conn, String p_username) throws SQLException {
    //     PreparedStatement ps = conn.prepareStatement("SELECT id, username, password, role FROM users WHERE username = ?");
    //     ps.setString(1, p_username);
    //     return ps.executeQuery();
    // }
    // $$;

    @Transactional(readOnly = true)
    public List<User> findUserByStoredProcedure(String username) {
        if (username == null) return Collections.emptyList();

        // Call the named stored procedure
        StoredProcedureQuery storedProcedure = em.createStoredProcedureQuery("find_users_by_username", User.class)
                .registerStoredProcedureParameter("p_username", String.class, jakarta.persistence.ParameterMode.IN)
                .setParameter("p_username", username); // Parameter binding prevents injection

        return storedProcedure.getResultList();
    }

    // A generic error page if needed
    public List<User> findUserSafe(String username) {
        return userRepository.findByUsername(username).map(List::of).orElse(Collections.emptyList());
    }
}