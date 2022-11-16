package telran.java2022.login.service;

import telran.java2022.login.dto.AddRoleDto;
import telran.java2022.login.dto.CreateUserDto;
import telran.java2022.login.dto.UpdateNameDto;
import telran.java2022.login.dto.UserDto;

public interface LoginService {

	UserDto addNewUser(CreateUserDto createUserDto);

	UserDto loginUser(String user);

	UserDto removeUser(String user);

	UserDto updateUser(String user, UpdateNameDto updateNameDto);

	AddRoleDto addRole(String user, String role);

	AddRoleDto removeRole(String user, String role);

//	void updatePassword(LoginAndChangePassDto loginAndChangePassDto);

	void updatePassword(String name, String newPassword);

}
