package co.edu.usco.pw.service;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if ("diegoc".equals(username)) {
			//usuario diegoc ----- clave 12345 encriptada
			return new User("diegoc", "$2a$10$AoydehHiLckZSUSvx0CU0uhwcTQhf6wJDzreEC4nw10fmlM36MuRu",
					new ArrayList<>());
		} else {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}
	}

}