package telran.java2022.login.dto;

import java.time.LocalDate;

import lombok.Getter;

@Getter
public class CreateUserDto {

	String login;
	String password;
	String firstName;
	String lastName;
//	LocalDate dateOfCreationPas;
}
