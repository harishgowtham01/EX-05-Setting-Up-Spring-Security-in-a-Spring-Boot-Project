# Ex No: 05 – Setting Up Spring Security in a Spring Boot Project

### Name: HARISH GOWTHAM E
### Register Number: 2305002009

## AIM

To develop a Spring Boot application that implements Spring Security to secure REST API endpoints using JWT-based authentication and authorization.

---

## ALGORITHM

1. Create a Spring Boot project using Maven.
2. Add the required dependencies:

   * Spring Web
   * Spring Security
   * JWT (JJWT)
3. Configure Spring Security using a `SecurityFilterChain`.
4. Disable CSRF and configure stateless session management.
5. Create a login endpoint to authenticate users.
6. Generate JWT tokens for valid users.
7. Create a JWT utility class to generate and validate tokens.
8. Implement a JWT filter to intercept requests and validate tokens.
9. Secure all endpoints except the login endpoint.
10. Run the application and test using Postman.
11. Verify that secured endpoints can only be accessed with a valid JWT token.

---

## PROJECT STRUCTURE

```text id="k9v3xp"
demo/
├── src/
│   └── main/
│       ├── java/
│       │   └── com/example/demo/
│       │       ├── Config/
│       │       │   └── SecurityConfig.java
│       │       ├── Controller/
│       │       │   └── AuthController.java
│       │       ├── Security/
│       │       │   ├── JwtFilter.java
│       │       │   └── JwtUtil.java
│       │       ├── LoginRequest.java
│       │       └── DemoApplication.java
│       └── resources/
│           └── application.properties
├── pom.xml
```

---

## PROGRAM

### pom.xml

```xml id="2z7d8m"
<dependencies>

    <!-- Spring Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <!-- JWT Dependencies -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.5</version>
    </dependency>

    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.5</version>
        <scope>runtime</scope>
    </dependency>

    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.5</version>
        <scope>runtime</scope>
    </dependency>

</dependencies>
```

### SecurityConfig.java

```java id="w7e2c4"
package com.example.demo.Config;

import com.example.demo.Security.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)
            throws Exception {

        http.csrf(csrf -> csrf.disable())

            .sessionManagement(session ->
                    session.sessionCreationPolicy(
                            SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/login").permitAll()
                    .anyRequest().authenticated())

            .addFilterBefore(
                    new JwtFilter(),
                    UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }
}
```

### AuthController.java

```java id="n3m5gx"
package com.example.demo.Controller;

import com.example.demo.LoginRequest;
import com.example.demo.Security.JwtUtil;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest req) {

        if ("admin".equals(req.getUsername())
                && "1234".equals(req.getPassword())) {

            return JwtUtil.generateToken(req.getUsername());
        }

        return "Invalid Credentials";
    }

    @GetMapping("/hello")
    public String hello() {
        return "Hello JWT Secure API";
    }
}
```

### JwtFilter.java

```java id="x6p2vs"
package com.example.demo.Security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication
        .UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context
        .SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String header =
                request.getHeader("Authorization");

        if (header != null &&
                header.startsWith("Bearer ")) {

            String token = header.substring(7);

            if (JwtUtil.validate(token)) {

                String username =
                        JwtUtil.extractUsername(token);

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                Collections.emptyList());

                SecurityContextHolder.getContext()
                        .setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }
}
```

### JwtUtil.java

```java id="d9y4ha"
package com.example.demo.Security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtil {

    private static final String SECRET =
            "mysecretkeymysecretkeymysecretkey123";

    private static final SecretKey KEY =
            Keys.hmacShaKeyFor(SECRET.getBytes());

    public static String generateToken(String username) {

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(
                    new Date(
                        System.currentTimeMillis()
                        + 1000 * 60 * 60))
                .signWith(KEY)
                .compact();
    }

    public static String extractUsername(String token) {

        return Jwts.parser()
                .verifyWith(KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public static boolean validate(String token) {

        try {
            extractUsername(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
```

### LoginRequest.java

```java id="r2k8md"
package com.example.demo;

public class LoginRequest {

    private String username;
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

---

## OUTPUT

<img width="669" height="438" alt="image" src="https://github.com/user-attachments/assets/135cc2b3-a419-4a17-9cdd-1959ba514aa0" />

<img width="678" height="443" alt="image" src="https://github.com/user-attachments/assets/b4741f5c-3d55-4da4-90ca-9421e6f801fa" />


## RESULT

Thus, a Spring Boot application was developed successfully to implement Spring Security using JWT-based authentication for securing REST API endpoints.
