package itx.fileserver.services;

import itx.fileserver.dto.*;
import itx.fileserver.services.data.AuditService;
import itx.fileserver.services.data.UserManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SecurityServiceImpl implements SecurityService {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityServiceImpl.class);

    private final UserManagerService userService;
    private final Map<String, UserData> authorizedSessions;
    private final AuditService auditService;

    @Autowired
    public SecurityServiceImpl(UserManagerService userService, AuditService auditService) {
        this.userService = userService;
        this.auditService = auditService;
        this.authorizedSessions = new ConcurrentHashMap<>();
    }

    @Override
    public UserData createAnonymousSession(String sessionId) {
        LOG.debug("createAnonymousSession {}", sessionId);
        UserData userData = new UserData("ANONYMOUS", userService.getAnonymousRole(), "");
        UserData previousData = authorizedSessions.put(sessionId, userData);
        createAnonymousSessionRecord(previousData, sessionId);
        return userData;
    }

    @Override
    public Optional<UserData> isAuthorized(String sessionId) {
        LOG.debug("isAuthorized {}", sessionId);
        return Optional.ofNullable(authorizedSessions.get(sessionId));
    }

    @Override
    public boolean isAnonymous(String sessionId) {
        LOG.debug("isAnonymous {}", sessionId);
        UserData userData = authorizedSessions.get(sessionId);
        if (userData != null && userData.getRoles().size() == 1) {
            return userData.getRoles().contains(userService.getAnonymousRole());
        }
        return false;
    }

    @Override
    public boolean isAuthorizedAdmin(String sessionId) {
        LOG.debug("isAuthorizedAdmin {}", sessionId);
        UserData userData = authorizedSessions.get(sessionId);
        if (userData != null) {
            return userData.getRoles().contains(userService.getAdminRole());
        }
        return false;
    }

    @Override
    public Optional<UserData> authorize(String sessionId, String username, String password) {
        LOG.debug("authorize {} {}", username, sessionId);
        Optional<UserData> userData = userService.getUser(username);
        if (userData.isPresent() && userData.get().verifyPassword(password)) {
            authorizedSessions.put(sessionId, userData.get());
            createLoginRecordOK(username, sessionId);
            return userData;
        }
        createLoginRecordFailed(username, sessionId);
        return Optional.empty();
    }

    @Override
    public void terminateSession(String sessionId) {
        LOG.debug("terminateSession {}", sessionId);
        UserData userDataAuthorized = authorizedSessions.remove(sessionId);
        createLogoutRecord(userDataAuthorized, sessionId);
    }

    @Override
    public Optional<Set<RoleId>> getRoles(String sessionId) {
        LOG.debug("getRoles {}", sessionId);
        UserData userData = authorizedSessions.get(sessionId);
        if (userData != null) {
            return Optional.of(userData.getRoles());
        }
        return Optional.empty();
    }

    @Override
    public Sessions getActiveSessions() {
        LOG.debug("getActiveSessions");
        List<SessionInfo> anonymous = new ArrayList<>();
        List<SessionInfo> users = new ArrayList<>();
        List<SessionInfo> admins = new ArrayList<>();
        authorizedSessions.forEach((id, user) -> {
            if (user.getRoles().contains(userService.getAdminRole())) {
                admins.add(new SessionInfo(id, user.getId(), user.getRoles()));
            } else if (user.getRoles().contains(userService.getAnonymousRole())) {
                anonymous.add(new SessionInfo(id, user.getId(), user.getRoles()));
            } else {
                users.add(new SessionInfo(id, user.getId(), user.getRoles()));
            }
        });
        return new Sessions(anonymous, users, admins);
    }

    /* AUDITING METHODS */

    private void createAnonymousSessionRecord(UserData previousData, String sessionId) {
        if (previousData == null) {
            AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                    AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "ANONYMOUS", "",
                    "OK", sessionId);
            auditService.storeAudit(auditRecord);
        }
    }

    private void createLoginRecordOK(String userId, String sessionId) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, userId, "", "OK",
                sessionId);
        auditService.storeAudit(auditRecord);
    }

    private void createLoginRecordFailed(String userId, String sessionId) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, userId, "", "ERROR",
                sessionId);
        auditService.storeAudit(auditRecord);
    }

    private void createLogoutRecord(UserData userDataAuthorized, String sessionId) {
        if (userDataAuthorized != null) {
            AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                    AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGOUT,
                    userDataAuthorized.getId(), "", "OK", sessionId);
            auditService.storeAudit(auditRecord);
        }
    }
}
