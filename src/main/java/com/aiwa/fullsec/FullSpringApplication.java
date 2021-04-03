package com.aiwa.fullsec;

import com.aiwa.fullsec.security.jwt.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class FullSpringApplication {

	public static void main(String[] args) {
		SpringApplication.run(FullSpringApplication.class, args);
	}

	@Bean
	public JwtConfig getJwtConfig(){
		return new JwtConfig();
	}
}
