/* Test-only fdatasync probe for the audit files of a shell-launched gateway. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int (*real_fdatasync)(int);
static int trace_fd;
static const char *audit_root;
static size_t audit_root_len;

__attribute__((constructor)) static void initialize(void) {
    const char *trace = getenv("AISP_SYNC_TRACE");
    audit_root = getenv("AISP_SYNC_AUDIT_DIR");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    if (trace == NULL || audit_root == NULL || real_fdatasync == NULL) {
        fputs("audit sync probe initialization failed\n", stderr);
        _exit(1);
    }
    audit_root_len = strlen(audit_root);
    trace_fd = open(trace, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0600);
    if (trace_fd < 0) {
        perror("open audit sync trace");
        _exit(1);
    }
}

static uint64_t nanoseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

int fdatasync(int fd) {
    uint64_t begin = nanoseconds();
    int rc = real_fdatasync(fd);
    int saved_errno = errno;
    uint64_t end = nanoseconds();
    char link[64], path[1024];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof(path));
    if (length > 0 && (size_t)length > audit_root_len &&
        memcmp(path, audit_root, audit_root_len) == 0 && path[audit_root_len] == '/') {
        uint64_t record[2] = {end - begin, (uint64_t)(rc == 0)};
        if (write(trace_fd, record, sizeof(record)) != sizeof(record)) {
            perror("write audit sync trace");
            _exit(1);
        }
    }
    errno = saved_errno;
    return rc;
}
