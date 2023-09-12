package itx.fileserver.filter;

import itx.fileserver.dto.SessionId;
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

        SessionId sessionId = new SessionId(httpSession.getId());
        Optional<UserData> userData = securityService.isAuthorized(sessionId);
        if (userData.isPresent()) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            String authHeader = request.getHeader("Authorization");
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
                                userData = securityService.authorize(sessionId, username, password);
                                if (userData.isEmpty()) {
                                    unauthorized(response, "Bad credentials");
                                }

                                filterChain.doFilter(servletRequest, servletResponse);
                            } else {
                                unauthorized(response, "Invalid authentication token");
                            }
                        } catch (UnsupportedEncodingException e) {
                            throw new Error("Couldn't retrieve authentication", e);
                        }
                    }
                }
            } else {
                unauthorized(response);
            }
        }
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        response.sendError(401, message);
    }

    private void unauthorized(HttpServletResponse response) throws IOException {
        unauthorized(response, "Unauthorized");
    }
}
