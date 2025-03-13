package org.example.springsecurity_jwt.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.example.springsecurity_jwt.entity.Role;
import org.example.springsecurity_jwt.entity.User;
import org.example.springsecurity_jwt.repository.UserRepository;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    //secret key
    private final SecretKey secretKey= Keys.secretKeyFor(SignatureAlgorithm.HS512);

    //expiration time
    private final int jwtExpirationInMilliSeconds = 86400000;

    private UserRepository userRepository;

    public JwtUtil(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    //generate token
    public String generateJwtToken(String username) {

        Optional<User> user = userRepository.findByUsername(username);
        Set<Role> roles = user.get().getRoles();

        //add roles to token
        return Jwts.builder().setSubject(username).claim("roles",roles.stream().
                map(role -> role.getName()).collect(Collectors.joining(",")))
                .setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime()+jwtExpirationInMilliSeconds))
                .signWith(secretKey).compact();
    }

    //extract username
    public String extractUsername(String token) {

        return Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }

    //extract roles
    public Set<String>extractRoles(String token) {
        String roleString = Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token).getBody()
                .get("roles", String.class);

        return Set.of(roleString);
    }


        //token validation
        public boolean isTokenValid(String token)
        {
            try{
                Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token);
                return true;
            }
            catch (Exception e)
            {return false;}
        }

}
