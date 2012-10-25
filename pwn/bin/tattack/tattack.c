#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <string.h>

#define MAXFD 1024
#define BLOCK_SIZE 4096

char **inputs;
char *prog;
char **args;
int input_field;

int *counts;

char *const env[] = {"LD_PRELOAD=./libc", NULL};

void worker(int offset, int num) {
  int pid, numpids, waitret, i, fd, pipe_stdin[2], pipe_stdout[2], pids[num],
    pins[num], pouts[num], len, bufsizes[num], numbs[num], written;
  char *bufs[num];

  for (i = 0; i < num; i++) {
    bufs[i] = malloc(BLOCK_SIZE);
    bufsizes[i] = BLOCK_SIZE;
    numbs[i] = 0;
    if (pipe(pipe_stdin) == -1) {
      perror("pipe");
      exit(1);
    }
    if (pipe(pipe_stdout) == -1) {
      perror("pipe");
      exit(1);
    }

    switch (pid = fork()) {
    case -1:
      perror("fork");
      exit(1);
    case 0: // In child
      if (input_field > 0) {
        args[input_field] = inputs[i + offset];
      }

      close(pipe_stdin[1]); // write end
      close(pipe_stdout[0]); // read end

      dup2(pipe_stdin[0], 0); // in read
      dup2(pipe_stdout[1], 1); // out write
      dup2(1, 2); // err write

      for (fd = 3; fd < MAXFD; fd++) {
        close(fd);
      }

      ptrace(PTRACE_TRACEME, 0, 0, 0);
      execve(prog, args, env);
      // should never reach this line
      exit(1);
    default: // In parent
      /* printf(" %d\n", pid); */
      close(pipe_stdin[0]); // read end
      close(pipe_stdout[1]); // write end
      pids[i] = pid;
      pins[i] = pipe_stdin[1];
      pouts[i] = pipe_stdout[0];

      len = strlen(inputs[i + offset]);
      if (input_field == 0) {
        if (write(pins[i], inputs[i + offset], len) < len) {
          perror("write");
          exit(1);
        }
      }
    }
  }

  numpids = num;
  while (numpids) {
    pid = waitpid(-1, &waitret, 0);
    for (i = 0; pids[i] != pid; i++);
    if (WIFSTOPPED(waitret)) {
      ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
      counts[i + offset]++;
    } else {
      close(pins[i]);

      for (;;) {
        len = read(pouts[i], &bufs[i][numbs[i]], bufsizes[i] - numbs[i]);
        if (len == -1) {
          perror("read");
          exit(1);
        }
        if (len == 0) break;
        numbs[i] += len;
        if (numbs[i] == bufsizes[i]) {
          bufsizes[i] += BLOCK_SIZE;
          bufs[i] = realloc(bufs[i], bufsizes[i]);
        }
      }

      close(pouts[i]);
      numpids--;

      printf("%d %d %d ", i + offset, counts[i + offset], numbs[i]); fflush(stdout);
      written = 0;
      while ((written -= write(1, &bufs[i][written], numbs[i] - written)) > 0);
    }
  }
}

void fill(char *buf) {
  char c;
  int i = 0;
  while ((c = getchar()) > 0) buf[i++] = c;
  buf[i] = 0;
}

int main(int argc, char *argv[]) {
  int numargs, numinputs, numworkers, numcpus, i, offset, num, pipe_stdout[2],
    *pouts, len;
  char buf[PATH_MAX];
  // Parse input
  prog = malloc(PATH_MAX);
  fill(prog);

  fill(buf);
  sscanf(buf, "%d", &numargs);

  args = calloc(numargs, sizeof(char *));
  for (i = 0; i < numargs; i++) {
    args[i] = malloc(PATH_MAX);
    fill(args[i]);
  }

  fill(buf);
  sscanf(buf, "%d", &input_field);

  fill(buf);
  sscanf(buf, "%d", &numinputs);

  inputs = calloc(numinputs, sizeof(char *));
  for (i = 0; i < numinputs; i++) {
    inputs[i] = malloc(PATH_MAX);
    fill(inputs[i]);
  }

  // Map shared page for instruction counts
  counts = mmap(NULL,
                4096,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS,
                -1, 0);

  numcpus = sysconf(_SC_NPROCESSORS_ONLN);
  if (numinputs < numcpus) {
    numworkers = numinputs;
  } else {
    numworkers = numcpus;
  }

  pouts = calloc(numworkers, sizeof(int));

  for (offset = 0, i = 0; i < numworkers; i++) {
    // share remaining inputs between remaining workers
    num = (numinputs - offset) / (numworkers - i);
    /* printf("%d, %d\n", offset, num); */
    if (pipe(pipe_stdout) == -1) {
      perror("pipe");
      exit(1);
    }
    switch (fork()) {
    case -1:
      perror("fork");
      exit(1);
    case 0: // child
      close(pipe_stdout[0]); // read end
      dup2(pipe_stdout[1], 1);
      dup2(1, 2);
      worker(offset, num);
      exit(0);
    default: // parent
      close(pipe_stdout[1]); // write end
      pouts[i] = pipe_stdout[0];
    }
    offset += num;
  }
  for (i = 0; i < numworkers; i++) wait(NULL);

  for (i = 0; i < numworkers; i++) {
    for (;;) {
      len = read(pouts[i], buf, sizeof(buf));
      if (len <= 0) break;
      while ((len -= write(1, buf, len)) > 0);
    }
  }

  return 0;
}
