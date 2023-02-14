package fx24.backend.springsecurity.service;

import fx24.backend.springsecurity.dto.UserAuthenticationDto;
import fx24.backend.springsecurity.model.AuthenticationRequest;
import fx24.backend.springsecurity.model.RegisterRequest;

public interface AuthenticationService {
    UserAuthenticationDto register(RegisterRequest request);

    UserAuthenticationDto authenticate(AuthenticationRequest request);
}
