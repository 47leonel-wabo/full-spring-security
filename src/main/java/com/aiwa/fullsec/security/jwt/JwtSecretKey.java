package com.aiwa.fullsec.security.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
public class JwtSecretKey {

    private final JwtConfig mJwtConfig;

    @Autowired
    public JwtSecretKey(JwtConfig jwtConfig) {
        mJwtConfig = jwtConfig;
    }

    @Bean
    public SecretKey getJwtSecretKey() {
        return Keys.hmacShaKeyFor(mJwtConfig.getSecretKey().getBytes());
    }
}
