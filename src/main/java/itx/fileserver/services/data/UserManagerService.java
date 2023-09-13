package itx.fileserver.services.data;

import itx.fileserver.dto.RoleId;
import itx.fileserver.dto.UserData;

import java.util.Collection;
import java.util.Optional;

public interface UserManagerService {

    Optional<UserData> getUser(String id);

    Collection<UserData> getUsers();

    void addUser(UserData userData);

    void removeUser(String id);

    RoleId getAnonymousRole();

    RoleId getAdminRole();

}
