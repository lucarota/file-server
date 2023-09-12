package itx.fileserver.test;

import itx.fileserver.dto.AuditConstants;
import itx.fileserver.dto.AuditQuery;
import itx.fileserver.dto.AuditRecord;
import itx.fileserver.services.data.AuditService;
import itx.fileserver.services.data.inmemory.AuditServiceInmemory;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditServiceInMemoryTest {

    @Test
    void testInMemotyRolingBuffer() {
        AuditService auditService = new AuditServiceInmemory(3);
        Collection<AuditRecord> audits = auditService.getAudits(AuditQuery.MATCH_ALL);
        assertEquals(0, audits.size());

        auditService.storeAudit(new AuditRecord(1546182100L, AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "user1", "", "login ok", null));
        auditService.storeAudit(new AuditRecord(1546182200L, AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "user1", "", "login ok", null));
        auditService.storeAudit(new AuditRecord(1546182300L, AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "user1", "", "login ok", null));

        audits = auditService.getAudits(AuditQuery.MATCH_ALL);
        assertEquals(3, audits.size());
        Iterator<AuditRecord> iterator = audits.iterator();
        AuditRecord auditRecord = iterator.next();
        assertEquals(1546182300L, auditRecord.getTimestamp());
        auditRecord = iterator.next();
        assertEquals(1546182200L, auditRecord.getTimestamp());
        auditRecord = iterator.next();
        assertEquals(1546182100L, auditRecord.getTimestamp());

        auditService.storeAudit(new AuditRecord(1546182400L, AuditConstants.CategoryUserAccess.NAME, AuditConstants.CategoryUserAccess.LOGIN, "user1", "", "login ok", null));

        audits = auditService.getAudits(AuditQuery.MATCH_ALL);
        assertEquals(3, audits.size());
        iterator = audits.iterator();
        auditRecord = iterator.next();
        assertEquals(1546182400L, auditRecord.getTimestamp());
        auditRecord = iterator.next();
        assertEquals(1546182300L, auditRecord.getTimestamp());
        auditRecord = iterator.next();
        assertEquals(1546182200L, auditRecord.getTimestamp());
    }

}
