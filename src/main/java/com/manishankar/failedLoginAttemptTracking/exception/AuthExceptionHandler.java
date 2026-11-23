package com.manishankar.failedLoginAttemptTracking.exception;

import com.manishankar.failedLoginAttemptTracking.dto.AuthenticationError;
import com.manishankar.failedLoginAttemptTracking.dto.LockoutResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Clock;
import java.time.Instant;

@RestControllerAdvice
public class AuthExceptionHandler {

    private final Clock clock;

    public AuthExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<LockoutResponse> handleLockedAccount(AccountLockedException exception) {
        Instant lockedUntil = exception.getLockedUntil();
        long remainingSeconds = lockedUntil == null
                ? 0
                : Math.max(0, lockedUntil.getEpochSecond() - clock.instant().getEpochSecond());
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(new LockoutResponse("Account is temporarily locked", lockedUntil, remainingSeconds));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<AuthenticationError> handleBadCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new AuthenticationError("Invalid username or password"));
    }
}
