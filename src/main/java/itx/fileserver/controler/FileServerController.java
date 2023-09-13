package itx.fileserver.controler;

import io.swagger.v3.oas.annotations.tags.Tag;
import itx.fileserver.dto.*;
import itx.fileserver.services.FileService;
import itx.fileserver.services.OperationNotAllowedException;
import itx.fileserver.services.SecurityService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

@RestController
@RequestMapping(path = FileServerController.URI_PREFIX)
@Tag(name = "File Server")
public class FileServerController {

    private static final Logger LOG = LoggerFactory.getLogger(FileServerController.class);

    public static final String URI_PREFIX = "/services/files";
    public static final String LIST_PREFIX = "/list/";
    public static final String DOWNLOAD_PREFIX = "/download/";
    public static final String UPLOAD_PREFIX = "/upload/";
    public static final String DELETE_PREFIX = "/delete/";
    public static final String CREATEDIR_PREFIX = "/createdir/";
    public static final String MOVE_PREFIX = "/move/";
    public static final String AUDIT_PREFIX = "/audit/";

    private final FileService fileService;
    private final SecurityService securityService;

    public FileServerController(FileService fileService, SecurityService securityService) {
        this.fileService = fileService;
        this.securityService = securityService;
    }

    @GetMapping(DOWNLOAD_PREFIX + "{*path}")
    public ResponseEntity<Resource> downloadFile(HttpSession httpSession,
                                                 @PathVariable(value = "path", required = false) String path) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path filePath = getPath(path);
                LOG.info("downloadFile: {}", filePath);
                Resource resource = fileService.loadFileAsResource(userData.get(), filePath);
                String contentType = "application/octet-stream";
                return ResponseEntity.ok().contentType(MediaType.parseMediaType(contentType))
                        .header(HttpHeaders.CONTENT_DISPOSITION,
                                "attachment; filename=\"" + resource.getFilename() + "\"").body(resource);
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (FileNotFoundException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @GetMapping(value = LIST_PREFIX + "{*path}", produces = "application/json")
    public ResponseEntity<FileList> getFiles(HttpSession httpSession,
                                             @PathVariable(value = "path", required = false) String path) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path filePath = getPath(path);
                LOG.info("getFiles: {}", filePath);
                FileList fileInfo = fileService.getFilesInfo(userData.get(), filePath);
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(fileInfo);
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (NoSuchFileException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping(value = UPLOAD_PREFIX + "{*path}", produces = "application/json")
    public ResponseEntity<Resource> fileUpload(HttpSession httpSession,
                                               @PathVariable(value = "path", required = false) String path,
                                               @RequestParam("file") MultipartFile file) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path filePath = getPath(path);
                LOG.info("upload: {}", filePath);
                fileService.saveFile(userData.get(), filePath, file.getInputStream());
                return ResponseEntity.ok().build();
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @DeleteMapping(value = DELETE_PREFIX + "{*path}", produces = "application/json")
    public ResponseEntity<Resource> delete(HttpSession httpSession,
                                           @PathVariable(value = "path", required = false) String path) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path filePath = getPath(path);
                LOG.info("delete: {}", filePath);
                fileService.delete(userData.get(), filePath);
                return ResponseEntity.ok().build();
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping(value = CREATEDIR_PREFIX + "{*path}", produces = "application/json")
    public ResponseEntity<Resource> createDirectory(HttpSession httpSession,
                                                    @PathVariable(value = "path", required = false) String path) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path filePath = getPath(path);
                LOG.info("createDirectory: {}", filePath);
                fileService.createDirectory(userData.get(), filePath);
                return ResponseEntity.ok().build();
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @PostMapping(MOVE_PREFIX + "{*path}")
    public ResponseEntity<Resource> move(HttpSession httpSession,
                                         @PathVariable(value = "path", required = false) String path,
                                         @RequestBody MoveRequest moveRequest) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path sourcePath = getPath(path);
                Path destinationPath = Paths.get(moveRequest.getDestinationPath());
                LOG.info("move: {}->{}", sourcePath, destinationPath);
                fileService.move(userData.get(), sourcePath, destinationPath);
                return ResponseEntity.ok().build();
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @GetMapping(AUDIT_PREFIX + "{*path}")
    public ResponseEntity<ResourceAccessInfo> getAuditInfo(HttpSession httpSession,
                                                           @PathVariable(value = "path", required = false) String path) {
        try {
            String sessionId = httpSession.getId();
            Optional<UserData> userData = securityService.isAuthorized(sessionId);
            if (userData.isPresent()) {
                Path sourcePath = getPath(path);
                LOG.info("audit: {}", sourcePath);
                ResourceAccessInfo resourceAccessInfo = fileService.getResourceAccessInfo(userData.get(), sourcePath);
                return ResponseEntity.ok().body(resourceAccessInfo);
            }
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (OperationNotAllowedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    private static Path getPath(String path) {
        if (path.startsWith("/")) {
            return Paths.get(path.substring(1));
        } else {
            return Paths.get(path);
        }
    }

}