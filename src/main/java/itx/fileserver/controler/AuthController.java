package itx.fileserver.controler;

import io.swagger.v3.oas.annotations.tags.Tag;
import itx.fileserver.dto.LoginRequest;
import itx.fileserver.dto.UserData;
import itx.fileserver.services.SecurityService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping(path = "/services/auth")
@Tag(name="Auth")
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    private final SecurityService securityService;

    public AuthController(SecurityService securityService) {
        this.securityService = securityService;
    }

    @PostMapping("/login")
    public ResponseEntity<UserData> login(HttpSession httpSession, @RequestBody LoginRequest loginRequest) {
        LOG.info("login: {} {}", loginRequest.getUsername(), httpSession.getId());
        String sessionId = httpSession.getId();
        Optional<UserData> userData = securityService.authorize(sessionId, loginRequest.getUsername(), loginRequest.getPassword());
        return userData.map(data -> ResponseEntity.ok().body(data))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.BAD_REQUEST).build());
    }

    @GetMapping("/logout")
    public ResponseEntity<Void> logout(HttpSession httpSession) {
        LOG.info("logout: {}", httpSession.getId());
        String sessionId = httpSession.getId();
        securityService.terminateSession(sessionId);
        httpSession.invalidate();
        return ResponseEntity.ok().build();
    }

}
