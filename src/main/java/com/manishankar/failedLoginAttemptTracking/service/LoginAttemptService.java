package com.manishankar.failedLoginAttemptTracking.service;

import com.manishankar.failedLoginAttemptTracking.entity.UserAccount;
import com.manishankar.failedLoginAttemptTracking.exception.AccountLockedException;
import com.manishankar.failedLoginAttemptTracking.repository.UserAccountRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class LoginAttemptService {

    static final int LOCKOUT_THRESHOLD = 5;
    static final Duration LOCKOUT_DURATION = Duration.ofMinutes(1);

    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final String dummyPasswordHash;

    public LoginAttemptService(
            UserAccountRepository userAccountRepository,
            PasswordEncoder passwordEncoder,
            Clock clock
    ) {
        this.userAccountRepository = userAccountRepository;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Transactional(noRollbackFor = AuthenticationException.class)
    public UserAccount authenticate(String username, String password) {
        if (username == null || username.isBlank() || password == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        Optional<UserAccount> result = userAccountRepository.findForAuthenticationByUsername(username.trim());
        if (result.isEmpty()) {
            passwordEncoder.matches(password, dummyPasswordHash);
            throw new BadCredentialsException("Invalid username or password");
        }

        UserAccount user = result.get();
        Instant now = clock.instant();
        if (!user.isAccountNonLocked()) {
            Instant lockedUntil = user.getLockTime() == null
                    ? null
                    : user.getLockTime().plus(LOCKOUT_DURATION);
            if (lockedUntil != null && now.isBefore(lockedUntil)) {
                throw new AccountLockedException(lockedUntil);
            }
            user.unlock();
        }

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            user.recordFailedAttempt(now, LOCKOUT_THRESHOLD);
            userAccountRepository.save(user);
            throw new BadCredentialsException("Invalid username or password");
        }

        user.unlock();
        return user;
    }
}
