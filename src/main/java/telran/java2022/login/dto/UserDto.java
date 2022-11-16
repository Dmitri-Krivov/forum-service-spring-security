package telran.java2022.login.dto;

import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {
	public UserDto(String login2, String password, String lastName2, String string) {
		// TODO Auto-generated constructor stub
	}
	String login;
	String firstName;
	String lastName;
	Set<String> roles;
}
