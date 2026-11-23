package com.manishankar.failedLoginAttemptTracking.auth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class GenerateHash {
    public static void main(String[] args) {
        // Implementation for generating hash
        System.out.println(new BCryptPasswordEncoder().encode("manishankar09"));
    }
}
