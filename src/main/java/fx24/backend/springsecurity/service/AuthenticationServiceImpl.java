package fx24.backend.springsecurity.service;

import fx24.backend.springsecurity.model.AuthenticationRequest;
import fx24.backend.springsecurity.dto.UserAuthenticationDto;
import fx24.backend.springsecurity.model.RegisterRequest;
import fx24.backend.springsecurity.config.JwtService;
import fx24.backend.springsecurity.constant.Role;
import fx24.backend.springsecurity.model.User;
import fx24.backend.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    @Override
    public UserAuthenticationDto register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .passwword(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        return UserAuthenticationDto.builder()
                .token(jwtToken)
                .build();
    }

    @Override
    public UserAuthenticationDto authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return UserAuthenticationDto.builder()
                .token(jwtToken)
                .build();

    }
}
