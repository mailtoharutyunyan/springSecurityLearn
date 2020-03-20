package my.java.security.app.security;

import com.google.common.collect.Sets;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

import static my.java.security.app.security.ApplicationUserPermission.*;

@RequiredArgsConstructor
@Getter
public enum ApplicationUserRole {


    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));

    private final Set<ApplicationUserPermission> permissions;

}
