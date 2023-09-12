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
    private final Map<SessionId, UserData> authorizedSessions;
    private final Map<SessionId, UserData> anonymousSessions;
    private final AuditService auditService;

    @Autowired
    public SecurityServiceImpl(UserManagerService userService, AuditService auditService) {
        this.userService = userService;
        this.auditService = auditService;
        this.authorizedSessions = new ConcurrentHashMap<>();
        this.anonymousSessions = new ConcurrentHashMap<>();
    }

    @Override
    public UserData createAnonymousSession(SessionId sessionId) {
        LOG.debug("createAnonymousSession {}", sessionId);
        UserData userData = new UserData(new UserId(sessionId.getId()), userService.getAnonymousRole(), "");
        UserData previousData = anonymousSessions.put(sessionId, userData);
        createAnonymousSessionRecord(previousData, sessionId);
        return userData;
    }

    @Override
    public Optional<UserData> isAuthorized(SessionId sessionId) {
        LOG.debug("isAuthorized {}", sessionId);
        return Optional.ofNullable(authorizedSessions.get(sessionId));
    }

    @Override
    public Optional<UserData> isAnonymous(SessionId sessionId) {
        LOG.debug("isAnonymous {}", sessionId);
        return Optional.ofNullable(anonymousSessions.get(sessionId));
    }

    @Override
    public boolean isAuthorizedAdmin(SessionId sessionId) {
        LOG.debug("isAuthorizedAdmin {}", sessionId);
        UserData userData = authorizedSessions.get(sessionId);
        if (userData != null) {
            return userData.getRoles().contains(userService.getAdminRole());
        }
        return false;
    }

    @Override
    public Optional<UserData> authorize(SessionId sessionId, String username, String password) {
        LOG.debug("authorize {} {}", username, sessionId);
        UserId userId = new UserId(username);
        Optional<UserData> userData = userService.getUser(userId);
        if (userData.isPresent() && userData.get().verifyPassword(password)) {
            authorizedSessions.put(sessionId, userData.get());
            anonymousSessions.remove(sessionId);
            createLoginRecordOK(username, sessionId);
            return userData;
        }
        createLoginRecordFailed(username, sessionId);
        return Optional.empty();
    }

    @Override
    public void terminateSession(SessionId sessionId) {
        LOG.debug("terminateSession {}", sessionId);
        UserData userDataAuthorized = authorizedSessions.remove(sessionId);
        UserData userDataAnonymous = anonymousSessions.remove(sessionId);
        createLogoutRecord(userDataAuthorized, userDataAnonymous, sessionId);
    }

    @Override
    public Optional<Set<RoleId>> getRoles(SessionId sessionId) {
        LOG.debug("getRoles {}", sessionId);
        UserData userData = authorizedSessions.get(sessionId);
        if (userData != null) {
            return Optional.of(userData.getRoles());
        } else {
            userData = anonymousSessions.get(sessionId);
            if (userData != null) {
                return Optional.of(userData.getRoles());
            }
        }
        return Optional.empty();
    }

    @Override
    public Sessions getActiveSessions() {
        LOG.debug("getActiveSessions");
        List<SessionInfo> anonymous = new ArrayList<>();
        List<SessionInfo> users = new ArrayList<>();
        List<SessionInfo> admins = new ArrayList<>();
        anonymousSessions.forEach((id,user) -> anonymous.add(new SessionInfo(id, user.getId(), user.getRoles())));
        authorizedSessions.forEach((id,user)->{
            if (user.getRoles().contains(userService.getAdminRole())) {
                admins.add(new SessionInfo(id, user.getId(), user.getRoles()));
            } else {
                users.add(new SessionInfo(id, user.getId(), user.getRoles()));
            }
        });
        return new Sessions(anonymous, users, admins);
    }

    /* AUDITING METHODS */

    private void createAnonymousSessionRecord(UserData previousData, SessionId sessionId) {
        if (previousData == null) {
            AuditRecord auditRecord
                    = new AuditRecord(Instant.now().getEpochSecond(), AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "ANONYMOUS", "", "OK", sessionId.getId());
            auditService.storeAudit(auditRecord);
        }
    }

    private void createLoginRecordOK(String userId, SessionId sessionId) {
        AuditRecord auditRecord
                = new AuditRecord(Instant.now().getEpochSecond(), AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, userId, "", "OK", sessionId.getId());
        auditService.storeAudit(auditRecord);
    }

    private void createLoginRecordFailed(String userId, SessionId sessionId) {
        AuditRecord auditRecord
                = new AuditRecord(Instant.now().getEpochSecond(), AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, userId, "", "ERROR", sessionId.getId());
        auditService.storeAudit(auditRecord);
    }

    private void createLogoutRecord(UserData userDataAuthorized, UserData userDataAnonymous, SessionId sessionId) {
        if (userDataAuthorized != null) {
            AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(), AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGOUT, userDataAuthorized.getId().getId(), "", "OK", sessionId.getId());
            auditService.storeAudit(auditRecord);
        }
        if (userDataAnonymous != null) {
            AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(), AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGOUT, "ANONYMOUS", "", "OK", sessionId.getId());
            auditService.storeAudit(auditRecord);
        }
    }
}
