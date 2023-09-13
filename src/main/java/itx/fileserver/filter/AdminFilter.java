package itx.fileserver.filter;

import itx.fileserver.services.SecurityService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;

public class AdminFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(AdminFilter.class);

    private final SecurityService securityService;

    public AdminFilter(SecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String sessionId = request.getSession().getId();
        if (securityService.isAuthorizedAdmin(sessionId)) {
            chain.doFilter(request, response);
        } else {
            LOG.info("session {} is not authorized admin session", sessionId);
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
    }
}
