package com.example.employeemgmtjwt.auth;

import com.example.employeemgmtjwt.enums.Role;
import com.example.employeemgmtjwt.model.Employee;
import com.example.employeemgmtjwt.repo.EmployeeRepo;
import com.example.employeemgmtjwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final EmployeeRepo employeeRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = Employee.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.TEACHER)
                .build();
        employeeRepo.save(user);
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        logger.info("Entering authenticate method");
        System.out.println(request.getEmail());
        System.out.println(request.getPassword());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );


        logger.debug("Authentication successful");

        var user = employeeRepo.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Token has not found"));

        var jwtToken = jwtService.generateToken(user);

        logger.debug("Token generated successfully");

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
