package com.aiwa.fullsec.security.jwt;

public class UserAuthenticationRequest {

    private String username;
    private String password;

    public UserAuthenticationRequest() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
