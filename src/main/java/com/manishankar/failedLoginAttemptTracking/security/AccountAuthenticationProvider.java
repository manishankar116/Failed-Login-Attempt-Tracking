package com.manishankar.failedLoginAttemptTracking.security;

import com.manishankar.failedLoginAttemptTracking.entity.UserAccount;
import com.manishankar.failedLoginAttemptTracking.service.LoginAttemptService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class AccountAuthenticationProvider implements AuthenticationProvider {

    private final LoginAttemptService loginAttemptService;

    public AccountAuthenticationProvider(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserAccount user = loginAttemptService.authenticate(
                authentication.getName(),
                authentication.getCredentials() == null ? null : authentication.getCredentials().toString()
        );
        AuthenticatedPrincipal principal = new AuthenticatedPrincipal(user.getId(), user.getUsername());
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
