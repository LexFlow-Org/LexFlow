/* macOS test-process-only crash injection. Production Rust source is unchanged.
 * Hooks apply solely to the exact synthetic vault path supplied by the runner.
 */
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static int stage_fd(int fd) {
    char actual[4096];
    const char *target = getenv("LEXFLOW_VALIDATION_TARGET");
    if (!target || fcntl(fd, F_GETPATH, actual) != 0) return 0;
    const char *last = strrchr(target, '/');
    if (!last) return 0;
    size_t parent_len = (size_t)(last - target + 1);
    return strncmp(actual, target, parent_len) == 0 &&
        strncmp(actual + parent_len, ".vault.lex.tmp.", 15) == 0;
}

static int phase_is(const char *name) {
    const char *phase = getenv("LEXFLOW_VALIDATION_PHASE");
    return phase && strcmp(phase, name) == 0;
}

static void checkpoint(const char *name) {
    const char *marker = getenv("LEXFLOW_VALIDATION_MARKER");
    if (!marker) _exit(98);
    int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(97);
    /* dyld does not interpose references originating in the replacement image.
     * Calling the original symbol directly avoids dlsym resolving our hook. */
    write(fd, name, strlen(name));
    close(fd);
    /* Parent observes this exact checkpoint, then sends SIGKILL. */
    kill(getpid(), SIGSTOP);
    _exit(96); /* It must never resume and silently count as a crash test. */
}

static ssize_t validation_write(int fd, const void *bytes, size_t count) {
    if (phase_is("mid_write") && count > 1024 && stage_fd(fd)) {
        ssize_t result = write(fd, bytes, count / 2);
        if (result < 0) return result;
        checkpoint("mid_write");
    }
    return write(fd, bytes, count);
}

static int validation_close(int fd) {
    /* Rust on macOS flushes through fcntl(F_FULLFSYNC), not fsync. The
     * staging descriptor closes after secure_write_create_new has flushed
     * successfully. Observe that real boundary without changing its I/O. */
    int matches = phase_is("after_temp_close") && stage_fd(fd);
    int result = close(fd);
    if (result == 0 && matches) checkpoint("after_temp_close");
    return result;
}

static int validation_rename(const char *from, const char *to) {
    const char *target = getenv("LEXFLOW_VALIDATION_TARGET");
    int matches = target && strcmp(target, to) == 0;
    if (matches && phase_is("before_rename")) checkpoint("before_rename");
    int result = rename(from, to);
    if (result == 0 && matches && phase_is("after_rename")) checkpoint("after_rename");
    return result;
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static const struct { const void *new_fn; const void *old_fn; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&original }
INTERPOSE(validation_write, write);
INTERPOSE(validation_close, close);
INTERPOSE(validation_rename, rename);
