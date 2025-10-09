package com.Security.Secureapp.repository;

import com.Security.Secureapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    // This Spring Data JPA method is safe against SQL Injection
    List<User> findByUsernameContainingIgnoreCase(String fragment);

    // If you need to expose a direct method for the stored procedure
    // @Procedure(procedureName = "find_users_by_username")
    // List<User> callFindUsersByUsername(@Param("p_username") String username);
    // However, it's often more flexible to call it via EntityManager.
}