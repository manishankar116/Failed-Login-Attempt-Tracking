package com.manishankar.failedLoginAttemptTracking.repository;

import com.manishankar.failedLoginAttemptTracking.entity.UserAccount;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select user from UserAccount user where lower(user.username) = lower(:username)")
    Optional<UserAccount> findForAuthenticationByUsername(@Param("username") String username);
}
