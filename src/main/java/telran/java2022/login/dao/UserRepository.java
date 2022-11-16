package telran.java2022.login.dao;

import org.springframework.data.repository.CrudRepository;

import telran.java2022.login.model.UserAccount;

public interface UserRepository extends CrudRepository<UserAccount, String> {

}
