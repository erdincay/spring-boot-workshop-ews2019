package de.osp.springbootworkshop.application.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

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
        String header = request.getHeader(AUTHORIZATION);

        if (StringUtils.isEmpty(header)) {
            LOG.warn("received request with no HTTP Header {}", AUTHORIZATION);
            return failure();
        }

        LOG.info("received request with HTTP header {} as {}", AUTHORIZATION, header);

        if (!header.startsWith("Bearer ")) {
            LOG.warn("received request with HTTP header {} but not as 'Bearer' token", AUTHORIZATION);
            return failure();
        }

        String token = header.replace("Bearer ", "");

        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
        } catch (JWTVerificationException e) {
            LOG.error("received request with HTTP header {} and as 'Bearer' token but token cannot be verified", AUTHORIZATION, e);
            return failure();
        }

        DecodedJWT decoded;

        try {
            decoded = JWT.decode(token);
        } catch (JWTDecodeException e) {
            LOG.error("received request with HTTP header {} and as 'Bearer' token but token cannot be decoded", AUTHORIZATION, e);
            return failure();
        }

        String subject = decoded.getSubject();

        if (StringUtils.isEmpty(subject)) {
            LOG.warn("received request with HTTP header {} and as 'Bearer' token but with no or empty subject", AUTHORIZATION);
            return failure();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        try {
            Claim rolesClaim = decoded.getClaim("roles");

            List<String> roles = rolesClaim.asList(String.class);

            if(roles != null) {
                for(String role : roles) {
                    authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
                }
            }
        } catch (JWTDecodeException e) {
            LOG.warn("received request with HTTP header {} and as 'Bearer' token but the 'roles' claim cannot be decoded", AUTHORIZATION);
            return failure();
        }

        return success(subject, authorities);
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
