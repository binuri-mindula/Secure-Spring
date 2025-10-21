package com.Security.Secureapp.service; // Or a dedicated 'security' package

import com.Security.Secureapp.model.User;
import com.Security.Secureapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections; // For empty list

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Note: Spring Security's UserDetails expects a Collection<GrantedAuthority> for roles.
        // If your User model stores roles as a single String (e.g., "ADMIN"), you'll need to convert it.
        // Assuming your User.getRole() returns a single string like "ADMIN", "USER", etc.
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword()) // Passwords from the DB are already encoded by UserService.init()
                .roles(user.getRole()) // Assumes roles are comma-separated or a single role string
                .build();
    }
}