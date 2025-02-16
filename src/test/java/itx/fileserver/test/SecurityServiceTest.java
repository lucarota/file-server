package itx.fileserver.test;

import itx.fileserver.config.FileServerConfig;
import itx.fileserver.dto.RoleId;
import itx.fileserver.dto.Sessions;
import itx.fileserver.dto.UserData;
import itx.fileserver.services.SecurityService;
import itx.fileserver.services.SecurityServiceImpl;
import itx.fileserver.services.data.AuditService;
import itx.fileserver.services.data.UserManagerService;
import itx.fileserver.services.data.inmemory.AuditServiceInmemory;
import itx.fileserver.services.data.inmemory.UserManagerServiceInmemory;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SecurityServiceTest {

    private static final String authorizedSessionJoe = "SessionJoe";
    private static final String authorizedSessionJane = "SessionJane";
    private static final String authorizedSessionAdmin = "SessionAdmin";
    private static final String anonymousSession = "SessionAnonymous";
    private static final String notExistingSession  = "notexisting";
    private static final String validPassword = "secret";
    private static final String invalidPassword = "xxxx";

    @Test
    void testValidLoginAndSession() {
        FileServerConfig fileServerConfig = TestUtils.createFileServerConfigForSecurityService();
        UserManagerService userManagerService = new UserManagerServiceInmemory(fileServerConfig);
        AuditService auditService = new AuditServiceInmemory(1024);
        SecurityService securityService = new SecurityServiceImpl(userManagerService, auditService);
        Optional<UserData> authorized;
        Optional<Set<RoleId>> roles;
        Sessions activeSessions;

        activeSessions = securityService.getActiveSessions();
        assertEquals(0, activeSessions.getAnonymousSessions().size());
        assertEquals(0, activeSessions.getUserSessions().size());
        assertEquals(0, activeSessions.getAdminSessions().size());

        //login session 1
        authorized = securityService.authorize(authorizedSessionJoe, "joe", validPassword);
        assertTrue(authorized.isPresent());
        assertTrue(authorized.get().verifyPassword(validPassword));
        roles = securityService.getRoles(authorizedSessionJoe);
        assertTrue(roles.isPresent());
        authorized = securityService.isAuthorized(authorizedSessionJoe);
        assertTrue(authorized.isPresent());

        //login session 2
        authorized = securityService.authorize(authorizedSessionJane, "jane", validPassword);
        assertTrue(authorized.isPresent());
        assertTrue(authorized.get().verifyPassword(validPassword));
        roles = securityService.getRoles(authorizedSessionJane);
        assertTrue(roles.isPresent());
        authorized = securityService.isAuthorized(authorizedSessionJane);
        assertTrue(authorized.isPresent());

        activeSessions = securityService.getActiveSessions();
        assertEquals(0, activeSessions.getAnonymousSessions().size());
        assertEquals(2, activeSessions.getUserSessions().size());
        assertEquals(0, activeSessions.getAdminSessions().size());

        //logout both sessions
        securityService.terminateSession(authorizedSessionJoe);
        securityService.terminateSession(authorizedSessionJane);

        //check session 1 status
        authorized = securityService.isAuthorized(authorizedSessionJoe);
        assertFalse(authorized.isPresent());

        //check session 2 status
        authorized = securityService.isAuthorized(authorizedSessionJane);
        assertFalse(authorized.isPresent());

        activeSessions = securityService.getActiveSessions();
        assertEquals(0, activeSessions.getAnonymousSessions().size());
        assertEquals(0, activeSessions.getUserSessions().size());
        assertEquals(0, activeSessions.getAdminSessions().size());

    }

    @Test
    void testInvalidSession() {
        FileServerConfig fileServerConfig = TestUtils.createFileServerConfigForSecurityService();
        UserManagerService userManagerService = new UserManagerServiceInmemory(fileServerConfig);
        AuditService auditService = new AuditServiceInmemory(1024);
        SecurityService securityService = new SecurityServiceImpl(userManagerService, auditService);
        Optional<UserData> authorized;
        Optional<Set<RoleId>> roles;
        Sessions activeSessions;

        roles = securityService.getRoles(notExistingSession);
        assertFalse(roles.isPresent());
        authorized = securityService.isAuthorized(notExistingSession);
        assertFalse(authorized.isPresent());

        activeSessions = securityService.getActiveSessions();
        assertEquals(0, activeSessions.getAnonymousSessions().size());
        assertEquals(0, activeSessions.getUserSessions().size());
        assertEquals(0, activeSessions.getAdminSessions().size());
    }

    @Test
    void testInvalidLogin() {
        FileServerConfig fileServerConfig = TestUtils.createFileServerConfigForSecurityService();
        UserManagerService userManagerService = new UserManagerServiceInmemory(fileServerConfig);
        AuditService auditService = new AuditServiceInmemory(1024);
        SecurityService securityService = new SecurityServiceImpl(userManagerService, auditService);
        Optional<UserData> authorized;
        Optional<Set<RoleId>> roles;

        authorized = securityService.authorize(authorizedSessionJoe, "joe", invalidPassword);
        assertFalse(authorized.isPresent());
        authorized = securityService.isAuthorized(authorizedSessionJoe);
        assertFalse(authorized.isPresent());
        roles = securityService.getRoles(authorizedSessionJoe);
        assertFalse(roles.isPresent());

        authorized = securityService.authorize(authorizedSessionJane, "jane", invalidPassword);
        assertFalse(authorized.isPresent());
        authorized = securityService.isAuthorized(authorizedSessionJane);
        assertFalse(authorized.isPresent());
        roles = securityService.getRoles(authorizedSessionJane);
        assertFalse(roles.isPresent());
    }

    @Test
    void testAnonymousSession() {
        FileServerConfig fileServerConfig = TestUtils.createFileServerConfigForSecurityService();
        UserManagerService userManagerService = new UserManagerServiceInmemory(fileServerConfig);
        AuditService auditService = new AuditServiceInmemory(1024);
        SecurityService securityService = new SecurityServiceImpl(userManagerService, auditService);
        Optional<UserData> authorized;
        UserData anonymousUser;
        Sessions activeSessions;

        //create anonymous session for valid user and anonymous one
        anonymousUser = securityService.createAnonymousSession(authorizedSessionJane);
        assertNotNull(anonymousUser);
        anonymousUser = securityService.createAnonymousSession(anonymousSession);
        assertNotNull(anonymousUser);
        assertTrue(securityService.isAnonymous(authorizedSessionJane));
        assertTrue(securityService.isAnonymous(anonymousSession));

        //login one valid user (not admin)
        authorized = securityService.authorize(authorizedSessionJane, "jane", validPassword);
        assertTrue(authorized.isPresent());
        assertTrue(authorized.get().verifyPassword(validPassword));

        //verify if sessions have correct access privileges
        assertTrue(securityService.isAuthorized(authorizedSessionJane).isPresent());

        assertFalse(securityService.isAnonymous(authorizedSessionJane));
        assertTrue(securityService.isAnonymous(anonymousSession));

        assertFalse(securityService.isAuthorizedAdmin(authorizedSessionJane));
        assertFalse(securityService.isAuthorizedAdmin(anonymousSession));

        activeSessions = securityService.getActiveSessions();
        assertEquals(1, activeSessions.getAnonymousSessions().size());
        assertEquals(1, activeSessions.getUserSessions().size());
        assertEquals(0, activeSessions.getAdminSessions().size());

        //terminate both sessions
        securityService.terminateSession(authorizedSessionJane);
        securityService.terminateSession(anonymousSession);

        //verify if sessions have correct access privileges after session termination
        assertFalse(securityService.isAuthorized(authorizedSessionJane).isPresent());
        assertFalse(securityService.isAuthorized(anonymousSession).isPresent());

        assertFalse(securityService.isAnonymous(authorizedSessionJane));
        assertFalse(securityService.isAnonymous(anonymousSession));

        assertFalse(securityService.isAuthorizedAdmin(authorizedSessionJane));
        assertFalse(securityService.isAuthorizedAdmin(anonymousSession));
    }

    @Test
    void testAdminSession() {
        FileServerConfig fileServerConfig = TestUtils.createFileServerConfigForSecurityService();
        UserManagerService userManagerService = new UserManagerServiceInmemory(fileServerConfig);
        AuditService auditService = new AuditServiceInmemory(1024);
        SecurityService securityService = new SecurityServiceImpl(userManagerService, auditService);
        Optional<UserData> authorized;
        UserData anonymousUser;
        Sessions activeSessions;

        //create anonymous session for valid users
        anonymousUser = securityService.createAnonymousSession(authorizedSessionJane);
        assertNotNull(anonymousUser);
        anonymousUser = securityService.createAnonymousSession(authorizedSessionAdmin);
        assertNotNull(anonymousUser);
        assertTrue(securityService.isAnonymous(authorizedSessionJane));
        assertTrue(securityService.isAnonymous(authorizedSessionAdmin));

        //login one valid users (one admin, one ordinary user)
        authorized = securityService.authorize(authorizedSessionJane, "jane", validPassword);
        assertTrue(authorized.isPresent());
        assertTrue(authorized.get().verifyPassword(validPassword));
        authorized = securityService.authorize(authorizedSessionAdmin, "master", validPassword);
        assertTrue(authorized.isPresent());
        assertTrue(authorized.get().verifyPassword(validPassword));

        //verify if sessions have correct access privileges
        assertTrue(securityService.isAuthorized(authorizedSessionJane).isPresent());
        assertTrue(securityService.isAuthorized(authorizedSessionAdmin).isPresent());

        assertFalse(securityService.isAnonymous(authorizedSessionJane));
        assertFalse(securityService.isAnonymous(authorizedSessionAdmin));

        assertFalse(securityService.isAuthorizedAdmin(authorizedSessionJane));
        assertTrue(securityService.isAuthorizedAdmin(authorizedSessionAdmin));

        activeSessions = securityService.getActiveSessions();
        assertEquals(0, activeSessions.getAnonymousSessions().size());
        assertEquals(1, activeSessions.getUserSessions().size());
        assertEquals(1, activeSessions.getAdminSessions().size());

        //terminate both sessions
        securityService.terminateSession(authorizedSessionJane);
        securityService.terminateSession(authorizedSessionAdmin);

        //verify if sessions have correct access privileges after session termination
        assertFalse(securityService.isAuthorized(authorizedSessionJane).isPresent());
        assertFalse(securityService.isAuthorized(authorizedSessionAdmin).isPresent());

        assertFalse(securityService.isAnonymous(authorizedSessionJane));
        assertFalse(securityService.isAnonymous(authorizedSessionAdmin));

        assertFalse(securityService.isAuthorizedAdmin(authorizedSessionJane));
        assertFalse(securityService.isAuthorizedAdmin(authorizedSessionAdmin));
    }

}
