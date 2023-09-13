package itx.fileserver.dto;

import java.util.Set;

public class SessionInfo {

    private final String id;
    private final String userId;
    private final Set<RoleId> roles;

    public SessionInfo(String id, String userId, Set<RoleId> roles) {
        this.id = id;
        this.userId = userId;
        this.roles = roles;
    }

    public String getId() {
        return id;
    }

    public String getUserId() {
        return userId;
    }

    public Set<RoleId> getRoles() {
        return roles;
    }

}
