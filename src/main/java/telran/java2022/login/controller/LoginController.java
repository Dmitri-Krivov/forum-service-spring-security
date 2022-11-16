package telran.java2022.login.controller;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import telran.java2022.login.dto.AddRoleDto;
import telran.java2022.login.dto.CreateUserDto;
import telran.java2022.login.dto.UpdateNameDto;
import telran.java2022.login.dto.UserDto;
import telran.java2022.login.service.LoginService;

@RestController
@RequestMapping("/account")
@RequiredArgsConstructor
public class LoginController {

	final LoginService loginService;

	@PostMapping("/register")
	public UserDto addUser(@RequestBody CreateUserDto CreateUserDto) {
		return loginService.addNewUser(CreateUserDto);
	}

	@PostMapping("/login")
//	public UserDto loginUser(@RequestHeader("Authorization") String token, Principal principal) {
	public UserDto loginUser(Principal principal) {
//		String[] basicAuthStrings = token.split(" ");
//		String decode = new String(Base64.getDecoder().decode(basicAuthStrings[1]));
//		String[] credential = decode.split(":");
//		return loginService.loginUser(credential[0]);
		return loginService.loginUser(principal.getName());

	}

	@DeleteMapping("/user/{user}")
	public UserDto removeUser(@PathVariable String user) {
		return loginService.removeUser(user);
	}

	@PutMapping("/user/{user}")
	public UserDto updateUser(@RequestBody UpdateNameDto updateNameDto,
			@PathVariable String user) {
		return loginService.updateUser(user, updateNameDto);
	}

	@PutMapping("/user/{user}/role/{role}")
	public AddRoleDto addRole(@PathVariable String user, @PathVariable String role) {
		return loginService.addRole(user, role);
	}

	@DeleteMapping("/user/{user}/role/{role}")
	public AddRoleDto removeRole(@PathVariable String user, @PathVariable String role) {
		return loginService.removeRole(user, role);
	}

//	@PutMapping("/user/password")
//	@ResponseStatus(HttpStatus.NO_CONTENT)
//	public void updatePassword(@RequestBody LoginAndChangePassDto loginAndChangePassDto) {
//		loginService.updatePassword(loginAndChangePassDto);
//	}

	@PutMapping("/user/password")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void updatePassword(Principal principal, @RequestHeader("X-Password") String newPassword) {
		loginService.updatePassword(principal.getName(), newPassword);
	}

}
