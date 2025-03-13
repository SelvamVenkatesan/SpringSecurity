package org.example.springsecurity_jwt.controller;

import org.example.springsecurity_jwt.dto.RegisterRequest;
import org.example.springsecurity_jwt.entity.Role;
import org.example.springsecurity_jwt.entity.User;
import org.example.springsecurity_jwt.repository.RoleRepository;
import org.example.springsecurity_jwt.repository.UserRepository;
import org.example.springsecurity_jwt.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;


    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //register user api
    @PostMapping("/register")
    public ResponseEntity<String>register(@RequestBody RegisterRequest registerRequest) {

        //check if username already exits
        if(userRepository.findByUsername(registerRequest.getUsername()).isPresent()){
            return  ResponseEntity.badRequest().body("Username is already taken");
        }

        User newUser=new User();
        newUser.setUsername(registerRequest.getUsername());
        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

        //convert role names to role entity and assign to user
        Set<Role> roles=new HashSet<>();
        for(String role:registerRequest.getRoles()){

            Role roleName=roleRepository.findByName(role).orElseThrow(()->new RuntimeException("Role Not Found"));
            roles.add(roleName);
        }
        newUser.setRoles(roles);
        userRepository.save(newUser);

        return ResponseEntity.ok().body("User registered successfully");
    }


    //login api
    @PostMapping("/login")
    public ResponseEntity<String>login(@RequestBody User loginRequest) {

        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }
        catch (Exception e){
            e.printStackTrace();
        }

        String token= jwtUtil.generateJwtToken(loginRequest.getUsername());
        return ResponseEntity.ok().body(token);
    }


}
