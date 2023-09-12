package itx.fileserver.config;

import itx.fileserver.filter.AdminFilter;
import itx.fileserver.filter.BasicAuthFilter;
import itx.fileserver.services.SecurityService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServletFilterConfig {

    private static final Logger LOG = LoggerFactory.getLogger(ServletFilterConfig.class);

    private final SecurityService securityService;

    private final HttpSession httpSession;
    private final FileServerConfig fileServerConfig;

    public ServletFilterConfig(SecurityService securityService, HttpSession httpSession,
                               FileServerConfig fileServerConfig) {
        this.securityService = securityService;
        this.httpSession = httpSession;
        this.fileServerConfig = fileServerConfig;
    }

    @Bean
    public FilterRegistrationBean<AdminFilter> adminFilter() {
        LOG.info("registering admin filter");
        FilterRegistrationBean<AdminFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new AdminFilter(securityService));
        registrationBean.addUrlPatterns("/services/admin/*");
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<BasicAuthFilter> filesFilter() {
        LOG.info("registering admin filter");
        FilterRegistrationBean<BasicAuthFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new BasicAuthFilter(securityService, httpSession, fileServerConfig.getRealm()));
        registrationBean.addUrlPatterns("/services/files/*");
        return registrationBean;
    }
}
