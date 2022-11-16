package telran.java2022.security.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.login.dao.UserRepository;
import telran.java2022.login.model.UserAccount;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

		final UserRepository repository;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		UserAccount userAccount = repository.findById(username).orElseThrow(()->new UsernameNotFoundException(username));
		
		String [] roles = userAccount.getRoles().stream()
				.map(r->"ROLE "+r.toUpperCase())
				.toArray(String[]::new);
		return new User(username, userAccount.getPassword(), AuthorityUtils.createAuthorityList(roles ));
	}

}