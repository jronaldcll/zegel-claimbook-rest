package com.zegel.claim_book.negocio;

import com.zegel.claim_book.entidades.seguridad.User;
import com.zegel.claim_book.repositorio.UserRepositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserNegocio {

    @Autowired
    private UserRepositorio userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User grabar(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public List<User> obtenerUsuarios() {
        return (List<User>) userRepository.findAll();
    }

    public User actualizar(User user) {
        if (userRepository.existsById(user.getId())) {
            return userRepository.save(user);
        } else {
            return null; // Manejar el caso donde el usuario no existe
        }
    }

    public User borrarUsuario(Long id) {
        User user = userRepository.findById(id).orElse(null);
        if (user != null) {
            userRepository.delete(user);
        }
        return user;
    }

    public User buscarPorId(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public User buscarPorUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
