package com.aiwa.fullsec.security.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserDao mAppUserDao;

    @Autowired
    public AppUserDetailsService(@Qualifier("fake-repo") AppUserDao appUserDao) {
        mAppUserDao = appUserDao;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return mAppUserDao.selectAppUserDetailsByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User with username "+username+" not found"));
    }
}
