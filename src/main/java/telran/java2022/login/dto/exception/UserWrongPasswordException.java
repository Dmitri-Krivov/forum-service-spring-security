package telran.java2022.login.dto.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import lombok.NoArgsConstructor;

@NoArgsConstructor
@ResponseStatus(HttpStatus.CONFLICT)
public class UserWrongPasswordException extends RuntimeException {
	private static final long serialVersionUID = 4387793719137314638L;

	public UserWrongPasswordException(String login) {
		super(" Dear '" + login + "' you entered the wrong password");

	}
}