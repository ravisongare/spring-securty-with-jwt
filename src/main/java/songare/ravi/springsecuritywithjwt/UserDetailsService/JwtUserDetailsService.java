package songare.ravi.springsecuritywithjwt.UserDetailsService;

import org.springframework.security.core.userdetails.User;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("ravi".equals(username)) {
            return new User("ravi",
                    "$2a$12$OVn/ecJiuVEp73qtAOqciOgE.eF3bKMYzYl/NskkKOD.m8GR9WcQS",//password
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }
}
