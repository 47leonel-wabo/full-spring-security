package com.aiwa.fullsec.security.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig mJwtConfig;
    private final SecretKey mSecretKey;

    @Autowired
    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        mJwtConfig = jwtConfig;
        mSecretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authorization = request.getHeader(mJwtConfig.getAuthorizationHeader());
        if (Strings.isNullOrEmpty(authorization) || !authorization.startsWith(mJwtConfig.getTokenPrefix().concat(" "))) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.replace(mJwtConfig.getTokenPrefix().concat(" "), "");
        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(mSecretKey)
                    .parseClaimsJws(token);

            Claims jwsBody = claimsJws.getBody();
            String username = jwsBody.getSubject();

            var authorities = (List<Map<String, String>>) jwsBody.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            simpleGrantedAuthorities
                    );
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        } catch (JwtException e) {
            throw new IllegalCallerException(String.format("Token %s not Truest", token));
        }
        filterChain.doFilter(request, response);
    }
}
