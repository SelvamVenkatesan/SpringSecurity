package org.example.springsecurity_jwt.controller;

import org.example.springsecurity_jwt.entity.Role;
import org.example.springsecurity_jwt.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${role.admin}")
    private String roleAdmin;

    @Value("${role.user}")
    private String roleUser;

    @GetMapping("/protected-data")
    public ResponseEntity<String> getProtectedData(@RequestHeader("Authorization")String token) {

        if (token == null && token.startsWith("Bearer ")) {

            String jwtToken = token.substring(7);

            try
            {
                if(jwtUtil.isTokenValid(jwtToken))
                {
                    String username=jwtUtil.extractUsername(jwtToken);//extract username
                    Set<String> roles=jwtUtil.extractRoles(jwtToken);//extract roles for particular user

                    if(roles.contains(roleAdmin))
                        return ResponseEntity.ok("You are admin");
                    else if (roles.contains(roleUser))
                        return ResponseEntity.ok("You are user");
                    else
                        return ResponseEntity.status(403).body("Access denied:Ypu Dont Have Permission");

                }
            }
            catch (Exception e)
            {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid Token");
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization Failed");
    }

}
