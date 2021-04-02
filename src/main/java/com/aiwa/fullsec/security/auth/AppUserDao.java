package com.aiwa.fullsec.security.auth;

import java.util.Optional;

public interface AppUserDao {
    Optional<AppUserDetails> selectAppUserDetailsByUsername(String username);
}
