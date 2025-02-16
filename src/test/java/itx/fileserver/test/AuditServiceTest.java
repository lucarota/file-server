package itx.fileserver.test;

import itx.fileserver.dto.AuditConstants;
import itx.fileserver.dto.AuditQuery;
import itx.fileserver.dto.AuditRecord;
import itx.fileserver.services.data.AuditService;
import itx.fileserver.services.data.filesystem.AuditServiceFilesystem;
import itx.fileserver.services.data.filesystem.PersistenceService;
import itx.fileserver.services.data.inmemory.AuditServiceInmemory;
import itx.fileserver.test.mocks.PersistenceServiceImpl;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Paths;
import java.util.Collection;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditServiceTest {

    public static Stream<Arguments> data() {
        return Stream.of(
                Arguments.of( createInmemoryAuditService() ),
                Arguments.of( createFilesystemAuditService() )
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchAll(AuditService auditService) {
        Collection<AuditRecord> audits = auditService.getAudits(AuditQuery.MATCH_ALL);
        assertEquals(10, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchCategory(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder().withCategory(AuditConstants.CategoryUserAccess.NAME).build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(2, audits.size());

        auditQuery = AuditQuery.newBuilder().withCategory(AuditConstants.CategoryFileAccess.NAME).build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(8, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchAction(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder().withAction(AuditConstants.CategoryUserAccess.LOGIN).build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(1, audits.size());

        auditQuery = AuditQuery.newBuilder().withAction(AuditConstants.CategoryFileAccess.DOWNLOAD).build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(2, audits.size());

        auditQuery = AuditQuery.newBuilder().withAction(AuditConstants.CategoryFileAccess.LIST_DIR).build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(3, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchUser(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder().withUserId("user1").build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(8, audits.size());

        auditQuery = AuditQuery.newBuilder().withUserId("user2").build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(2, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchTimeIntervals(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder().from(1546182200L).to(1546182700L).build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(6, audits.size());

        auditQuery = AuditQuery.newBuilder().to(1546182700L).build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(8, audits.size());

        auditQuery = AuditQuery.newBuilder().from(1546182200L).build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(8, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchResourcePatterns(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder().withResourcePattern("user1/files/**").build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(6, audits.size());

        auditQuery = AuditQuery.newBuilder().withResourcePattern("**/*.txt").build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(5, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchMessagePatterns(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder().withMessagePattern("ok").build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(6, audits.size());

        auditQuery = AuditQuery.newBuilder().withMessagePattern("error.*").build();
        audits = auditService.getAudits(auditQuery);
        assertEquals(2, audits.size());
    }

    @ParameterizedTest
    @MethodSource("data")
    void testQueryAuditServiceMatchMixed(AuditService auditService) {
        AuditQuery auditQuery = AuditQuery.newBuilder()
                .withUserId("user1")
                .withResourcePattern("user1/files/*")
                .withMessagePattern("ok")
                .build();
        Collection<AuditRecord> audits = auditService.getAudits(auditQuery);
        assertEquals(4, audits.size());
    }

    private static void populateAudits(AuditService auditService) {
        auditService.storeAudit(new AuditRecord(1546182000L, AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "user1", "", "login ok", null));
        auditService.storeAudit(new AuditRecord(1546182100L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.DOWNLOAD, "user1", "user1/files/data.txt", "ok", ""));
        auditService.storeAudit(new AuditRecord(1546182200L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.UPLOAD, "user1", "user1/files/upload.txt", "ok", ""));
        auditService.storeAudit(new AuditRecord(1546182300L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.DELETE, "user1", "user1/files/upload.txt", "ok", ""));
        auditService.storeAudit(new AuditRecord(1546182400L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.UPLOAD, "user2", "user1/files/upload.txt", "ok", ""));
        auditService.storeAudit(new AuditRecord(1546182500L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.LIST_DIR, "user1", "user1/files/", "ok", ""));
        auditService.storeAudit(new AuditRecord(1546182600L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.LIST_DIR, "user1", "user1/", "ok", ""));
        auditService.storeAudit(new AuditRecord(1546182700L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.LIST_DIR, "user1", "user1/xxx/", "error: file does not exits", ""));
        auditService.storeAudit(new AuditRecord(1546182800L, AuditConstants.CategoryFileAccess.NAME, AuditConstants.CategoryFileAccess.DOWNLOAD, "user2", "user1/files/zzzz.txt", "error: file does not exits", ""));
        auditService.storeAudit(new AuditRecord(1546182900L, AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGOUT, "user1", "", "logout ok", null));
    }

    public static AuditService createInmemoryAuditService() {
        AuditService auditService = new AuditServiceInmemory(1024);
        populateAudits(auditService);
        return auditService;
    }

    public static AuditService createFilesystemAuditService() {
        PersistenceService persistenceService = new PersistenceServiceImpl();
        AuditService auditService = new AuditServiceFilesystem(Paths.get("some", "path"), persistenceService);
        populateAudits(auditService);
        return auditService;
    }

}
