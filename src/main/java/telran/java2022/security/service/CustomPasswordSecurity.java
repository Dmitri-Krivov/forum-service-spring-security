package telran.java2022.security.service;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.login.dao.UserRepository;
import telran.java2022.login.model.UserAccount;

@Service("customPassSecurity")
@RequiredArgsConstructor
public class CustomPasswordSecurity {
	@Value("${password.period:30}")
	long DAYSTOCHAINGEPASSWORD;
	final UserRepository userRepository;
	
	public boolean checkPass(String id) {
		LocalDate localDat = LocalDate.now();
		UserAccount user = userRepository.findById(id).orElse(null);
		if(ChronoUnit.DAYS.between(user.getDateOfCreationPas(), localDat)>DAYSTOCHAINGEPASSWORD) {
			return false;
		}
		return true;
	}
}
