package itx.fileserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.event.EventListener;

@SpringBootApplication(scanBasePackages = {"itx.fileserver"})
public class FileServer extends SpringBootServletInitializer {

    private static final Logger LOG = LoggerFactory.getLogger(FileServer.class);

    public static void main(String[] args) {
        SpringApplication.run(FileServer.class);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void doLogAfterStartup() {
        LOG.info("START MICROSERVICE NOW");
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        //set register error pagefilter false
        setRegisterErrorPageFilter(false);
        builder.sources(FileServer.class);
        return builder;
    }
}
