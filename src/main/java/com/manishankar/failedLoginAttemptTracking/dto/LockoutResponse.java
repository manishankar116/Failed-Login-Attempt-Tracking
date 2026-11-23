package com.manishankar.failedLoginAttemptTracking.dto;

import java.time.Instant;

public record LockoutResponse(String message, Instant lockedUntil, long remainingSeconds) {
}
