/* Stay alive after spawning the next program.

   exec would replace this image and drop it from the child's parent chain.
   The child keeps this executable path as an ancestor for as long as it runs.
*/
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        execv(argv[1], argv + 1);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {}
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}
