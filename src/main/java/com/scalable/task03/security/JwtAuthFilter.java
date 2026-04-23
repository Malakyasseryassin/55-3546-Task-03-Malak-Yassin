package com.scalable.task03.security;

import com.scalable.task03.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // TODO: See Task 3 spec — JwtAuthFilter.
        // The chain.doFilter(...) call at the end of this method MUST stay outside the try block.

        // 1. Extract Authorization header
        String authHeader = request.getHeader("Authorization");

        // 2. If header is missing or doesn't start with Bearer → continue
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        try {
            // TODO

            // 3. Extract token (remove "Bearer ")
            String token = authHeader.substring(7);

            // 4. Extract username from token
            String username = jwtService.extractUsername(token);

            // 5. Validate token
            if (username != null
                    && SecurityContextHolder.getContext().getAuthentication() == null
                    && jwtService.isTokenValid(token)) {

                // 6. Load user details
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 7. Create authentication object
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                // 8. Set authentication in SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        } catch (Exception e) {
            // Token invalid — continue without authentication; Spring Security will return 401.
        }

        chain.doFilter(request, response);
    }
}