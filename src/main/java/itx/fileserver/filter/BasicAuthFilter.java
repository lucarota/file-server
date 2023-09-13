package itx.fileserver.filter;

import itx.fileserver.dto.UserData;
import itx.fileserver.services.SecurityService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Optional;
import java.util.StringTokenizer;

public class BasicAuthFilter implements Filter {

    private final String realm;

    private final SecurityService securityService;
    private final HttpSession httpSession;

    public BasicAuthFilter(SecurityService securityService, HttpSession httpSession, String realm) {
        this.securityService = securityService;
        this.httpSession = httpSession;
        this.realm = realm;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String sessionId = httpSession.getId();
        String authHeader = request.getHeader("Authorization");
        if (securityService.isAnonymous(sessionId) && authHeader != null) {
            handleBasicAuth(authHeader, sessionId, response);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private void handleBasicAuth(String authHeader, String sessionId, HttpServletResponse response) throws IOException {
        if (authHeader != null) {
            StringTokenizer st = new StringTokenizer(authHeader);
            if (st.hasMoreTokens()) {
                String basic = st.nextToken();
                if (basic.equalsIgnoreCase("Basic")) {
                    try {
                        String credentials = new String(Base64.getDecoder().decode(st.nextToken()));
                        String[] cred = credentials.split(":");
                        if (cred.length == 2) {
                            String username = cred[0].trim();
                            String password = cred[1].trim();
                            Optional<UserData> userData = securityService.authorize(sessionId, username, password);
                            if (userData.isEmpty()) {
                                unauthorized(response, "Bad credentials");
                            }
                        } else {
                            unauthorized(response, "Invalid authentication token");
                        }
                    } catch (UnsupportedEncodingException e) {
                        throw new Error("Couldn't retrieve authentication", e);
                    }
                }
            }
        }
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        response.sendError(401, message);
    }
}
