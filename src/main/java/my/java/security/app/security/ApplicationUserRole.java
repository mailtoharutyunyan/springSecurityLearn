package my.java.security.app.security;

import com.google.common.collect.Sets;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static my.java.security.app.security.ApplicationUserPermission.COURSE_READ;
import static my.java.security.app.security.ApplicationUserPermission.COURSE_WRITE;
import static my.java.security.app.security.ApplicationUserPermission.STUDENT_READ;
import static my.java.security.app.security.ApplicationUserPermission.STUDENT_WRITE;

@RequiredArgsConstructor
@Getter
public enum ApplicationUserRole {
  STUDENT(Sets.newHashSet()),
  ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
  ADMIN_TRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

  private final Set<ApplicationUserPermission> permissions;

  public Set<SimpleGrantedAuthority> grantedAuthority() {
    Set<SimpleGrantedAuthority> simpleGrantedAuthorities =
        getPermissions().stream()
            .map(permission -> new SimpleGrantedAuthority(permission.getPermissions()))
            .collect(Collectors.toSet());
    simpleGrantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
    return simpleGrantedAuthorities;
  }
}
