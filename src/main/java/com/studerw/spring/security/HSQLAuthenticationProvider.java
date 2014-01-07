package com.studerw.spring.security;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.studerw.spring.model.User;

@Service("hsqlAuthenticationProvider")
public class HSQLAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider{

    private static final Logger log = LoggerFactory.getLogger(HSQLAuthenticationProvider.class);

    protected DataSource ds;
    protected NamedParameterJdbcTemplate jdbcTemplate;

    @Autowired
    public void setDataSource(DataSource ds){
        log.trace("setDateSource()");
        this.ds = ds;
        this.jdbcTemplate = new NamedParameterJdbcTemplate(ds);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.trace("authenticate()");
        log.debug("authenticating: " + authentication);
        String clearText = String.valueOf(authentication.getCredentials());
        UserDetails userDetails = this.retrieveUser(authentication.getName(), (UsernamePasswordAuthenticationToken) authentication);

        if (!StringUtils.equals(clearText,  userDetails.getPassword())){
            throw new BadCredentialsException("invalid password");
        }
        if (!userDetails.isEnabled()){
            throw new BadCredentialsException("User not enabled");
        }
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        log.trace("additionalAuthenticaitonChecks()");
        log.debug("isEnabled: " + userDetails.isEnabled());
        if (!userDetails.isEnabled()){
            throw new BadCredentialsException("User not enabled");
        }
    }

    @Override
    @Transactional(readOnly = true)
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        log.trace("retrieveUser()");
        log.debug("retrieveing user: " + username);
        User user = null;
        try {
             user= this.read(username);
        }
        catch(Exception e){
            throw new UsernameNotFoundException("User " + username + " cannot be found");
        }

        String userName = user.getName();
        String pw = user.getPassword();
        String role = user.getRole();
        Collection<GrantedAuthority> auths = AuthorityUtils.createAuthorityList(role);
        boolean enabled = user.getActive();

        UserDetails userDetails = new org.springframework.security.core.userdetails.User(userName, pw, enabled, true, true, true, auths);
        log.debug("returning new userDetails: " + userDetails);
        return userDetails;
    }

    @Transactional(readOnly = true)
    protected User read(String name) {
        log.trace("read()");
        log.debug("reading user: " + name);
        String sql = "SELECT * FROM users WHERE UPPER(name) = :name";
        Map<String, Object> params = new HashMap<String, Object>();
        params.put("name", StringUtils.upperCase(name));
        User user = this.jdbcTemplate.queryForObject(sql, params, new UserRowMapper());
        return user;
    }

    private class UserRowMapper implements RowMapper<com.studerw.spring.model.User>{
        @Override
        public User mapRow(ResultSet rs, int rowNum) throws SQLException {
            User user = new com.studerw.spring.model.User();
            user.setId(StringUtils.trim(rs.getString("userid")));
            user.setPassword(StringUtils.trim(rs.getString("password")));
            user.setRole(StringUtils.trim(rs.getString("role")));
            user.setActive(rs.getBoolean("active"));
            log.trace(user.toString());
            return user;
        }

    }


}


