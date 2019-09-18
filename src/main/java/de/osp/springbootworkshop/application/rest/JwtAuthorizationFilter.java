package de.osp.springbootworkshop.application.rest;

import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private static final String ROLE_PREFIX = "ROLE_";
    private static final Logger LOG = getLogger(JwtAuthorizationFilter.class);
    private final RequestMatcher requestMatcher;

    public JwtAuthorizationFilter(RequestMatcher requestMatcher,
                                  AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.requestMatcher = requestMatcher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        if (requestMatcher.matches(request)) {
            Authentication authentication = doAuthenticate(request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private Authentication doAuthenticate(final HttpServletRequest request) {
        // TODO: implement me

        return null;
    }

    private Authentication success(final String subject,
                                   final List<GrantedAuthority> authorities) {
        return new UsernamePasswordAuthenticationToken(new JwtAuthenticatedPrincipal(subject), null, authorities);
    }

    private Authentication failure() {
        return new UsernamePasswordAuthenticationToken(null, null);
    }

    private static class JwtAuthenticatedPrincipal implements AuthenticatedPrincipal {
        private final String name;

        private JwtAuthenticatedPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }
}
