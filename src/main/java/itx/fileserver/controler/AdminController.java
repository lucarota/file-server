package itx.fileserver.controler;

import itx.fileserver.dto.*;
import itx.fileserver.services.FileService;
import itx.fileserver.services.OperationNotAllowedException;
import itx.fileserver.services.SecurityService;
import itx.fileserver.services.data.AuditService;
import itx.fileserver.services.data.FileAccessManagerService;
import itx.fileserver.services.data.UserManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping(path = "/services/admin")
public class AdminController {

    private static final Logger LOG = LoggerFactory.getLogger(AdminController.class);

    private final FileService fileService;
    private final SecurityService securityService;
    private final UserManagerService userManagerService;
    private final FileAccessManagerService fileAccessManagerService;
    private final AuditService auditService;
    private final HttpSession httpSession;

    @Autowired
    public AdminController(FileService fileService, SecurityService securityService,
                           UserManagerService userManagerService, FileAccessManagerService fileAccessManagerService,
                           AuditService auditService, HttpSession httpSession) {
        this.fileService = fileService;
        this.securityService = securityService;
        this.userManagerService = userManagerService;
        this.fileAccessManagerService = fileAccessManagerService;
        this.auditService = auditService;
        this.httpSession = httpSession;
    }

    @GetMapping("/storage/info")
    public ResponseEntity<FileStorageInfo> getStorageInfo() {
        LOG.info("getStorageInfo:");
        return ResponseEntity.ok().body(fileService.getFileStorageInfo());
    }

    @GetMapping("/sessions")
    public ResponseEntity<Sessions> getSessions() {
        LOG.info("getSessions:");
        return ResponseEntity.ok().body(securityService.getActiveSessions());
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> terminateSession(@PathVariable("sessionId") String sessionId) {
        LOG.info("terminateSession: {}", sessionId);
        //TODO: http session should be terminated as well
        securityService.terminateSession(new SessionId(sessionId));
        return ResponseEntity.ok().build();
    }

    @GetMapping("/users/all")
    public ResponseEntity<Collection<UserData>> getUsers() throws OperationNotAllowedException {
        LOG.info("getUsers:");
        UserData authorized = securityService.isAuthorized(new SessionId(httpSession.getId()))
                .orElseThrow(OperationNotAllowedException::new);
        createGetUsersAuditRecord(authorized);

        return ResponseEntity.ok().body(userManagerService.getUsers());
    }

    @GetMapping("/users/role/admin")
    public ResponseEntity<RoleId> getAdminRole() {
        LOG.info("getAdminRole:");
        return ResponseEntity.ok().body(userManagerService.getAdminRole());
    }

    @GetMapping("/users/role/anonymous")
    public ResponseEntity<RoleId> getAnonymousRole() {
        LOG.info("getAdminRole:");
        return ResponseEntity.ok().body(userManagerService.getAnonymousRole());
    }

    @PostMapping("/users/add")
    public ResponseEntity<Void> addUser(@RequestBody UserConfig userConfig) {
        LOG.info("addUser: {}", userConfig.getUsername());
        try {
            Set<RoleId> roles = new HashSet<>();
            userConfig.getRoles().forEach(r -> roles.add(new RoleId(r)));
            UserData userData = new UserData(new UserId(userConfig.getUsername()), roles, userConfig.getPassword());
            userManagerService.addUser(userData);
            UserData authorized = securityService.isAuthorized(new SessionId(httpSession.getId()))
                    .orElseThrow(OperationNotAllowedException::new);
            createCreateUserAuditRecord(authorized, userConfig);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @DeleteMapping("/users/remove/{userId}")
    public ResponseEntity<Void> removeUser(@PathVariable("userId") String userId) {
        LOG.info("removeUser: {}", userId);
        SessionId sessionId = new SessionId(httpSession.getId());
        Optional<UserData> authorized = securityService.isAuthorized(sessionId);
        if (authorized.isPresent() && (!userId.equals(authorized.get().getId().getId()))) {
            userManagerService.removeUser(new UserId(userId));
            createRemoveUserAuditRecord(authorized.get(), userId);
            return ResponseEntity.ok().build();
        } else {
            LOG.error("Can't delete current user {} ! Use different user account to delete this user.", userId);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/file/access/filters")
    public ResponseEntity<Collection<FilterConfig>> getFileAccessFilters() throws OperationNotAllowedException {
        LOG.info("getFileAccessFilters:");
        UserData authorized = securityService.isAuthorized(new SessionId(httpSession.getId()))
                .orElseThrow(OperationNotAllowedException::new);
        createGetFileAccessFiltersAuditRecord(authorized);
        return ResponseEntity.ok().body(fileAccessManagerService.getFilters());
    }

    @PostMapping("/file/access/filters")
    public ResponseEntity<Void> addFileAccessFilter(
            @RequestBody FilterConfig filterConfig) throws OperationNotAllowedException {
        LOG.info("addFileAccessFilter: {} {} {}", filterConfig.getPath(), filterConfig.getAccess(),
                filterConfig.getRoles());
        fileAccessManagerService.addFilter(filterConfig);
        UserData authorized = securityService.isAuthorized(new SessionId(httpSession.getId()))
                .orElseThrow(OperationNotAllowedException::new);
        createCreateFileAccessFilterAuditRecord(authorized, filterConfig);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/file/access/filters")
    public ResponseEntity<Void> removeFileAccessFilter(
            @RequestBody FilterConfig filterConfig) throws OperationNotAllowedException {
        LOG.info("removeFileAccessFilter: {} {} {}", filterConfig.getPath(), filterConfig.getAccess(),
                filterConfig.getRoles());
        fileAccessManagerService.removeFilter(filterConfig);
        UserData authorized = securityService.isAuthorized(new SessionId(httpSession.getId()))
                .orElseThrow(OperationNotAllowedException::new);
        createRemoveFileAccessFilterAuditRecord(authorized, filterConfig);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/audit")
    public ResponseEntity<Collection<AuditRecord>> getAuditRecords(@RequestBody AuditQuery auditQuery) {
        LOG.info("getAuditRecords:");
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        return ResponseEntity.ok().body(audits);
    }

    /* AUDIT METHODS */

    public void createGetUsersAuditRecord(UserData userData) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryAdminAccess.NAME, AuditConstants.CategoryAdminAccess.GET_USERS,
                userData.getId().getId(), "", "OK", "");
        auditService.storeAudit(auditRecord);
    }

    public void createCreateUserAuditRecord(UserData userData, UserConfig userConfig) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryAdminAccess.NAME, AuditConstants.CategoryAdminAccess.CREATE_USER,
                userData.getId().getId(), "", "OK", userConfig.getUsername());
        auditService.storeAudit(auditRecord);
    }

    public void createRemoveUserAuditRecord(UserData userData, String userId) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryAdminAccess.NAME, AuditConstants.CategoryAdminAccess.DELETE_USER,
                userData.getId().getId(), "", "OK", userId);
        auditService.storeAudit(auditRecord);
    }

    public void createGetFileAccessFiltersAuditRecord(UserData userData) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryAdminAccess.NAME, AuditConstants.CategoryAdminAccess.GET_ACCESS_FILTERS,
                userData.getId().getId(), "", "OK", "");
        auditService.storeAudit(auditRecord);
    }

    public void createCreateFileAccessFilterAuditRecord(UserData userData, FilterConfig filterConfig) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryAdminAccess.NAME, AuditConstants.CategoryAdminAccess.CREATE_ACCESS_FILTER,
                userData.getId().getId(), "", "OK", filterConfig.getAccess());
        auditService.storeAudit(auditRecord);
    }

    public void createRemoveFileAccessFilterAuditRecord(UserData userData, FilterConfig filterConfig) {
        AuditRecord auditRecord = new AuditRecord(Instant.now().getEpochSecond(),
                AuditConstants.CategoryAdminAccess.NAME, AuditConstants.CategoryAdminAccess.DELETE_ACCESS_FILTER,
                userData.getId().getId(), "", "OK", filterConfig.getAccess());
        auditService.storeAudit(auditRecord);
    }

}
