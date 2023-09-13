package itx.fileserver.test;

import itx.fileserver.config.FileServerConfig;
import itx.fileserver.services.FileAccessService;
import itx.fileserver.services.FileAccessServiceImpl;
import itx.fileserver.services.SecurityService;
import itx.fileserver.services.SecurityServiceImpl;
import itx.fileserver.services.data.AuditService;
import itx.fileserver.services.data.FileAccessManagerService;
import itx.fileserver.services.data.UserManagerService;
import itx.fileserver.services.data.inmemory.AuditServiceInmemory;
import itx.fileserver.services.data.inmemory.FileAccessManagerServiceInmemory;
import itx.fileserver.services.data.inmemory.UserManagerServiceInmemory;
import itx.fileserver.dto.RoleId;
import itx.fileserver.dto.UserData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileAccessServiceTest {

    private static final String authorizedSessionJoe = "SessionJoe";
    private static final String authorizedSessionJane = "SessionJane";
    private static final String authorizedSessionPublic = "SessionPublic";
    private static final String validPassword = "secret";

    private static FileAccessService fileAccessService;
    private static SecurityService securityService;

    @BeforeAll
    public static void init() {
        FileServerConfig fileServerConfig = TestUtils.createFileServerConfigForFileAccessService();
        UserManagerService userManagerService = new UserManagerServiceInmemory(fileServerConfig);
        FileAccessManagerService fileAccessManagerService = new FileAccessManagerServiceInmemory(fileServerConfig);
        AuditService auditService = new AuditServiceInmemory(1024);
        securityService = new SecurityServiceImpl(userManagerService, auditService);
        fileAccessService = new FileAccessServiceImpl(fileAccessManagerService);
        Optional<UserData> authorized;

        authorized = securityService.authorize(authorizedSessionJoe, "joe", validPassword);
        assertTrue(authorized.isPresent());
        authorized = securityService.authorize(authorizedSessionJane, "jane", validPassword);
        assertTrue(authorized.isPresent());
        authorized = securityService.authorize(authorizedSessionPublic, "public", validPassword);
        assertTrue(authorized.isPresent());
    }

    public static Stream<Arguments> data() {
        return Stream.of(
                Arguments.of( authorizedSessionJoe, "joe/data", true, true ),
                Arguments.of( authorizedSessionJoe, "joe/data.txt", true, true ),
                Arguments.of( authorizedSessionJoe, "jane/data.txt", false, false ),

                Arguments.of( authorizedSessionJoe, "secret.pdf", false, false ),
                Arguments.of( authorizedSessionJane, "secret.pdf", false, false ),
                Arguments.of( authorizedSessionPublic, "secret.pdf", false, false ),

                Arguments.of( authorizedSessionJane, "jane/data", true, true ),
                Arguments.of( authorizedSessionJane, "jane/data.txt", true, true ),
                Arguments.of( authorizedSessionJane, "jane/nested/data.txt", true, true ),

                Arguments.of( authorizedSessionJane, "joe/for-jane/data", true, true ),
                Arguments.of( authorizedSessionJane, "joe/for-jane/data.txt", true, true ),
                Arguments.of( authorizedSessionJane, "joe/for-public/data.txt", true, false ),
                Arguments.of( authorizedSessionJane, "joe/data.txt", false, false ),

                Arguments.of( authorizedSessionJoe, "public/data", true, true ),
                Arguments.of( authorizedSessionJoe, "public/readonly", true, true ),
                Arguments.of( authorizedSessionJoe, "public/readonly/image.jpg", true, false ),

                Arguments.of( authorizedSessionJane, "public/data", true, true ),
                Arguments.of( authorizedSessionJane, "public/readonly", true, true ),
                Arguments.of( authorizedSessionJane, "public/readonly/image.jpg", true, false ),

                Arguments.of( authorizedSessionPublic, "public/data", true, true ),
                Arguments.of( authorizedSessionPublic, "public/readonly", true, true ),
                Arguments.of( authorizedSessionPublic, "public/readonly/image.jpg", true, false ),
                Arguments.of( authorizedSessionPublic, "public/readonly/subdir/image.jpg", true, false )
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void testReadAccess(String sessionId, String path, boolean expectedCanRead, boolean ignored) {
        Optional<Set<RoleId>> roles = securityService.getRoles(sessionId);
        Path p = Paths.get(path);
        assertTrue(roles.isPresent());
        boolean canRead = fileAccessService.canRead(roles.get(), p);
        assertEquals(canRead, expectedCanRead);
    }

    @ParameterizedTest
    @MethodSource("data")
    void testWriteAccess(String sessionId, String path, boolean ignored, boolean expectedCanReadAndWrite) {
        Optional<Set<RoleId>> roles = securityService.getRoles(sessionId);
        Path p = Paths.get(path);
        assertTrue(roles.isPresent());
        boolean canReadAndWrite = fileAccessService.canReadAndWrite(roles.get(), p);
        assertEquals(canReadAndWrite, expectedCanReadAndWrite);
    }

}
