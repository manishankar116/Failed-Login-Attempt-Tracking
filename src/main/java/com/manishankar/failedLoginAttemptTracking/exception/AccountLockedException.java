package com.manishankar.failedLoginAttemptTracking.exception;

import org.springframework.security.authentication.LockedException;

import java.time.Instant;

public class AccountLockedException extends LockedException {

    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil) {
        super("Account is temporarily locked");
        this.lockedUntil = lockedUntil;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }
}
