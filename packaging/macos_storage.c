/* MIT: small SDK-backed bridge; never opens sockets or starts processes. */
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int okv_local_path(const char *path) {
    struct statfs *mounts;
    int count = getmntinfo(&mounts, MNT_NOWAIT);
    if (count <= 0) return -1;
    size_t longest = 0;
    int local = 0;
    for (int i = 0; i < count; i++) {
        const char *mount = mounts[i].f_mntonname;
        size_t n = strlen(mount);
        if (n >= longest && strncmp(path, mount, n) == 0 &&
            (n == 1 || path[n] == '/' || path[n] == '\0')) {
            longest = n;
            local = (mounts[i].f_flags & MNT_LOCAL) != 0 &&
                    strcmp(mounts[i].f_fstypename, "autofs") != 0;
        }
    }
    return local;
}

int okv_local_fd(int fd) {
    struct statfs mount;
    if (fstatfs(fd, &mount) != 0) return -1;
    return (mount.f_flags & MNT_LOCAL) != 0;
}

int okv_private_fd(int fd) {
    struct stat info;
    if (fstat(fd, &info) != 0) return -1;
    if (info.st_uid != geteuid() || !S_ISREG(info.st_mode) || info.st_nlink != 1) {
        errno = EPERM; return -1;
    }
    acl_t empty = acl_init(0);
    if (empty == NULL) return -1;
    int result = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED);
    int saved = errno;
    acl_free(empty);
    if (result != 0) { errno = saved; return -1; }
    return fchmod(fd, S_IRUSR | S_IWUSR);
}
