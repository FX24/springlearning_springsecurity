package fx24.backend.springsecurity.controller;

import fx24.backend.springsecurity.model.AuthenticationRequest;
import fx24.backend.springsecurity.dto.UserAuthenticationDto;
import fx24.backend.springsecurity.service.AuthenticationServiceImpl;
import fx24.backend.springsecurity.model.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationServiceImpl authenticationServiceImpl;

    @PostMapping("/register")
    public ResponseEntity<UserAuthenticationDto> register (
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authenticationServiceImpl.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<UserAuthenticationDto> register (
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationServiceImpl.authenticate(request));
    }
}
