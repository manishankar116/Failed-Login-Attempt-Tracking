package com.manishankar.failedLoginAttemptTracking;

import com.manishankar.failedLoginAttemptTracking.entity.UserAccount;
import com.manishankar.failedLoginAttemptTracking.exception.AccountLockedException;
import com.manishankar.failedLoginAttemptTracking.repository.UserAccountRepository;
import com.manishankar.failedLoginAttemptTracking.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LoginLockoutIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserAccountRepository userAccountRepository;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private UserAccount user;

    @BeforeEach
    void setUp() {
        userAccountRepository.deleteAll();
        user = userAccountRepository.saveAndFlush(
                UserAccount.provisioned("alice", passwordEncoder.encode("correct-password"))
        );
    }

    @Test
    void fifthConsecutiveFailureLocksAccountAndCorrectPasswordIsDeniedDuringLockout() {
        for (int attempt = 1; attempt <= 5; attempt++) {
            assertThatThrownBy(() -> loginAttemptService.authenticate("alice", "wrong-password"))
                    .isInstanceOf(BadCredentialsException.class);
        }

        UserAccount lockedUser = userAccountRepository.findById(user.getId()).orElseThrow();
        assertThat(lockedUser.getFailedAttempts()).isEqualTo(5);
        assertThat(lockedUser.isAccountNonLocked()).isFalse();
        assertThat(lockedUser.getLockTime()).isNotNull();

        assertThatThrownBy(() -> loginAttemptService.authenticate("alice", "correct-password"))
                .isInstanceOf(AccountLockedException.class)
                .satisfies(exception -> assertThat(((AccountLockedException) exception).getLockedUntil())
                        .isAfter(Instant.now()));
        assertThat(userAccountRepository.findById(user.getId()).orElseThrow().getFailedAttempts()).isEqualTo(5);
    }

    @Test
    void successfulLoginResetsCounterAndExpiredLock() {
        for (int attempt = 0; attempt < 3; attempt++) {
            assertThatThrownBy(() -> loginAttemptService.authenticate("alice", "wrong-password"))
                    .isInstanceOf(BadCredentialsException.class);
        }

        loginAttemptService.authenticate("alice", "correct-password");
        UserAccount afterSuccess = userAccountRepository.findById(user.getId()).orElseThrow();
        assertThat(afterSuccess.getFailedAttempts()).isZero();
        assertThat(afterSuccess.isAccountNonLocked()).isTrue();
        assertThat(afterSuccess.getLockTime()).isNull();

        UserAccount expiredLock = userAccountRepository.findById(user.getId()).orElseThrow();
        Instant expiredAt = Instant.now().minus(16, ChronoUnit.MINUTES);
        for (int attempt = 0; attempt < 5; attempt++) {
            expiredLock.recordFailedAttempt(expiredAt, 5);
        }
        userAccountRepository.saveAndFlush(expiredLock);

        loginAttemptService.authenticate("alice", "correct-password");
        UserAccount afterExpiry = userAccountRepository.findById(expiredLock.getId()).orElseThrow();
        assertThat(afterExpiry.getFailedAttempts()).isZero();
        assertThat(afterExpiry.isAccountNonLocked()).isTrue();
        assertThat(afterExpiry.getLockTime()).isNull();
    }

    @Test
    void loginEndpointReturns423AndRemainingTimeForLockedAccounts() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            login("wrong-password").andExpect(status().isUnauthorized());
        }

        login("correct-password")
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.lockedUntil").isNotEmpty())
                .andExpect(jsonPath("$.remainingSeconds").value(
                        org.hamcrest.Matchers.greaterThan(0)
                ));
    }

    @Test
    void loginEndpointEstablishesSessionOnSuccessfulAuthentication() throws Exception {
        login("correct-password")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
    }

    @Test
    void unknownAccountsReceiveGenericBadCredentials() {
        assertThatThrownBy(() -> loginAttemptService.authenticate("unknown", "wrong-password"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid username or password");
    }

    private org.springframework.test.web.servlet.ResultActions login(String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"" + password + "\"}"));
    }
}
