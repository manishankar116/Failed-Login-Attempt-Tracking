package com.manishankar.failedLoginAttemptTracking.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
public class UserAccount implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked = true;

    @Column(name = "lock_time")
    private Instant lockTime;

    @Version
    @Column(nullable = false)
    private long version;

    protected UserAccount() {
    }

    public static UserAccount provisioned(String username, String passwordHash) {
        UserAccount user = new UserAccount();
        user.username = username.trim();
        user.passwordHash = passwordHash;
        return user;
    }

    public Long getId() {
        return id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public Instant getLockTime() {
        return lockTime;
    }

    public void recordFailedAttempt(Instant attemptedAt, int lockoutThreshold) {
        failedAttempts++;
        if (failedAttempts >= lockoutThreshold) {
            accountNonLocked = false;
            lockTime = attemptedAt;
        }
    }

    public void unlock() {
        failedAttempts = 0;
        accountNonLocked = true;
        lockTime = null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
