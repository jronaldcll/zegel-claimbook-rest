package com.zegel.claim_book.repositorio;

import com.zegel.claim_book.entidades.seguridad.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepositorio extends CrudRepository<User, Long> {
    User findByUsername(String username);
}