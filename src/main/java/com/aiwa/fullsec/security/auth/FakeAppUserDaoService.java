package com.aiwa.fullsec.security.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.aiwa.fullsec.security.ApplicationUserRoles.*;

@Repository("fake-repo")
public class FakeAppUserDaoService implements AppUserDao {

    private final PasswordEncoder mPasswordEncoder;

    @Autowired
    public FakeAppUserDaoService(PasswordEncoder passwordEncoder) {
        mPasswordEncoder = passwordEncoder;
    }

    @Override
    public Optional<AppUserDetails> selectAppUserDetailsByUsername(String username) {
        return getUserDetails().stream()
                .filter(appUserDetails -> appUserDetails.getUsername().equals(username))
                .findFirst();
    }

    private List<AppUserDetails> getUserDetails() {
        List<AppUserDetails> userDetails = Lists.newArrayList(
                new AppUserDetails(
                        STUDENT.getGrantedAuthorities(),
                        "ada",
                        mPasswordEncoder.encode("ada"),
                        true,
                        true,
                        true,
                        true
                ),
                new AppUserDetails(
                        ADMIN.getGrantedAuthorities(),
                        "assa",
                        mPasswordEncoder.encode("assa"),
                        true,
                        true,
                        true,
                        true
                ),
                new AppUserDetails(
                        TRAINEE.getGrantedAuthorities(),
                        "haile",
                        mPasswordEncoder.encode("haile"),
                        true,
                        true,
                        true,
                        true
                )
        );
        return userDetails;
    }
}
