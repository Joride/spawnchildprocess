#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

// printout functions for errors. Taken from man pages. Speed up finding out
// what is going on in case of errors. Keeping main code clearn. 
void printPipeError(int error);
void printForkError(int error);
void printSetenvError(int error);
void printExecError(int error);
void printWaitpidError(int error);
void printReadError(int error);

void waitForAChildToFinish(pid_t childPid);
char * readChildOutput(int filedes, int * bufferSize);

int main(int argc, char * argv[])
{
	char * childProcessPath = NULL;
	if (argc < 2)
	{
		// one argument needed: the path to the child process
		printf("Missing argument: provide the path the program to run as child process as argument\n");
		exit(EXIT_FAILURE);
	}
	else 
	{
		childProcessPath = argv[1];
	}

	// setup a pipe to read the stdout of the child.
	// This MUST be done before the call to `fork()`, so that both parent
	// and child process make use of the same pipe
    #define READ_END  0
    #define WRITE_END 1
    errno = 0;
    int pipefd[2];
    int success = pipe(pipefd);
	if (-1 == success) 
	{
		printPipeError(errno);
		exit(EXIT_FAILURE);
	}

	// On success, the PID of the child process is returned in the parent, 
	// and 0 is returned in the child. 
	errno = 0;

	// this is where a parallel u̶n̶i̶v̶e̶r̶s̶e̶ process get created
    pid_t pid = fork(); 
    if (pid < 0)
    {
    	// fork() failed
    	printForkError(errno);
    	exit(EXIT_FAILURE);
    }

	// fork() succeeded
    if (0 == pid)
    {
    	// this is the child process
    	// NOTE: if getppid() returns 1, this is because the parent process was
    	// finished by the time the child asks for its parent's pid. And when a
    	// process finishes, all its children are reassigned as children of the
    	// init process, which pid is 1.
    	//
    	// printf("I am the child process (as pid = %i), my pid is %i, my parent's pid is %i\n", pid, getpid(), getppid()); 
    	//printf("Child is now going to be replaced by another program using execv()\n");

    	// this process has no need to have access to the read end of the
    	// pipe. Close it immediately.
    	close(pipefd[READ_END]);
    	
    	// To capture the output of this child process, its standard output must
    	// instead of to standard out be routed into the pipe. This can be 
    	// arranged using the dup2 command. 
    	// A loop is needed to allow for the possibility of dup2 being 
    	// interrupted by a signal. 
    	//
    	// Note: this program effectively enters a busywait loop here until 
    	// dup2() succeeds
    	while ( ( dup2(pipefd[WRITE_END], STDOUT_FILENO) == -1) && (errno == EINTR)) {}

    	// now we can close the write end of the pipe as well, the process
    	// can use things like printf() to write into the pipe
    	close(pipefd[WRITE_END]);

    	// returns zero on success, or -1 on error, with errno set to indicate 
    	// the cause of the error.
    	errno = 0;
    	if (-1 == setenv("VERB" ,"GET", 1))
    	{
    		printSetenvError(errno);
    		exit(EXIT_FAILURE);
    	}

    	char * argv_list[] = { 
    		childProcessPath,
    		"argument at index 1",
    		NULL 
    	}; 
    	
    	// The exec() functions return only if an error has occurred.  The
    	// return value is -1, and errno is set to indicate the error.
    	errno = 0;
    	int execReturn = execv(childProcessPath, argv_list); 
    	if (execReturn < 0)
    	{
    		// error
    		printExecError(errno);
    		exit(EXIT_FAILURE);
    	}

    	// succesfully completed, but this should never be reached due to the 
    	// execv() call: if that call is succesfull this program is obliterated
    	// from existence
      	exit(0);
    }
    else 
    {
    	// this is the parent process
    	// printf("I am the parent process (as the child pid = %i), my pid is %d\n", pid, getpid()); 

    	// The parent process has no need to access the entrance to the pipe, so
    	// pipefd[WRITE_END] should be closed within this process:
		close(pipefd[WRITE_END]);

		int bufferSize = 0;
		printf("Going to read stdout from child...\n");
		char * output = readChildOutput(pipefd[READ_END], &bufferSize);
		if (NULL != output)
		{
     		printf("Child wrote to stdout:\n\"%.*s\"\n\n", bufferSize, output);
     		free(output);
     	}
     	printf("Done reading stdout from child.\n");

		#undef READ_END
    	#undef WRITE_END

    	// To parent program is effectively done here. To avoid the child from
    	// becoming a zombie process, the parent waits for it to be done,
    	// before stopping itself.
    	// NOTE: the readChildOutput() function is blocking until EOF is
    	// received. If the child writes to stdout and then exits, there
    	// is nothing to wait for anymore.
    	// Still, to clean up to process (and not have the init process take
    	// care of it for us), `wait()` needs to be called. Also, maybe the
    	// child does a lot more after writing to stdout.

    	// Wait for the child to terminate before terminating ourselves
    	printf("Waiting for child to finish...\n");
    	waitForAChildToFinish(pid);
    	printf("Done waiting for child.\n");
    }

    printf("Parent exits here.\n");
    // successfully done.
    return 0;
}

// This function is probably way more complicated than it needs to be
char * readChildOutput(int filedes, int * bufferSize)
{
	int bufferIndex = 0;
	int size = sizeof(char) * 10;
	char * buffer = malloc(size);
	while (1) 
	{
		errno = 0;
		
		ssize_t count = read(filedes, &buffer[bufferIndex], size - bufferIndex);
		if (-1 == count) 
		{
			printReadError(errno);
			free(buffer);
			if (NULL != bufferSize) { *bufferSize = 0; }
			return NULL;
		} 
		else if (0 == count)  
		{ 
			// done reading, return what was collected
			if (NULL != bufferSize)
			{
				*bufferSize = bufferIndex;
			}
			return buffer; 
		} 
		else  
		{
			bufferIndex += count;
			if (bufferIndex >= size)
			{
				size *= 2;
		        char * newBuffer = realloc(buffer, size);
		        if (NULL != newBuffer)
		        { buffer = newBuffer; }
				else 
				{ printf("ERROR: could not realloc buffer\n"); }
			}
		}
	}
}

void waitForAChildToFinish(pid_t pid)
{
	int status = 0;
	// on success, returns the process ID of the child whose state has 
	// changed (...)  On error, -1 is returned. errno is set to an 
	// appropriate value in the case of an error.
	pid_t waitResult = waitpid(pid, &status, 0);
	errno = 0;
	if (waitResult < 0)
	{
		printWaitpidError(errno);
	}
	else 
	{
		// WIFEXITED: returns a nonzero value if the child process
		// terminated normally
		// WIFEXITED: if WIFEXITED is true of status, this macro returns the
		// low-order 8 bits of the exit status value from the child process
		//
		// paraphrased: notmal termination, AND exit code is zero 
		if (WIFEXITED(status) && !WEXITSTATUS(status))
		{
			// success, we need no glory for doing our job
			// printf("Child program execution ended successfully\n"); 
		}
		// normal termination, AND non-zero exit code
		else if (WIFEXITED(status) && WEXITSTATUS(status))
		{ 
			// 127 exit code has specia meaning: "command not found".
			// possible problem with $PATH or a typo in execv() 
			// command earlier
            if (WEXITSTATUS(status) == 127) 
            {
                // execv failed 
                printf("Execv() failed: command not found\n"); 
            } 
            else if (WEXITSTATUS(status) == 126) 
            {
            	printf("Command invoked for child program cannot execute. Permission problem or command is not an executable.\n");
            }
            else if (WEXITSTATUS(status) == 128) 
            {
            	printf("Invalid argument to exit. Exit takes only integer args in the range 0 - 255.\n");
            }
            else if (WEXITSTATUS(status) == 130) 
            {
            	// Cntrol-C is fatal error signal 2 (130 = 128 + 2)
            	printf("Child program terminated by Control-C.\n");
            }
            else 
            {
            	printf("Child program terminated normally, but returned a non-zero status: %i\n", WEXITSTATUS(status));                 
            }
        } 
        else 
        {
        	printf("Child program terminated abnormally (e.g. by a signal)\n");
        }
	}
}

void printReadError(int error)
{
	switch (error)
	{
		case EWOULDBLOCK: 
        printf("The file descriptor fd refers to a file other than a socket and has been marked nonblocking (O_NONBLOCK), and the read would block.  See open(2) for further details on the O_NONBLOCK flag.\n");
        printf("The file descriptor fd refers to a socket and has been marked nonblocking (O_NONBLOCK), and the read would block.  POSIX.1-2001 allows either error to  be  returned  for this case, and does not require these constants to have the same value, so a portable application should check for both possibilities.\n"); break;
        case EBADF: printf("fd is not a valid file descriptor or is not open for reading.\n"); break;
        case EFAULT: printf("buf is outside your accessible address space.\n"); break;
        case EINTR: printf("The call was interrupted by a signal before any data was read; see signal(7).\n"); break;
        case EINVAL:
        printf("fd  is attached to an object which is unsuitable for reading; or the file was opened with the O_DIRECT flag, and either the address specified in buf, the value specified in count, or the file offset is not suitably aligned.\n");
        printf("fd was created via a call to timerfd_create(2) and the wrong size buffer was given to read(); see timerfd_create(2) for further information.\n");
        break;
        case EIO: printf("I/O error.  This will happen for example when the process is in a background process group, tries to read from its controlling terminal, and either  it  is  ignoring  or blocking SIGTTIN or its process group is orphaned.  It may also occur when there is a low-level I/O error while reading from a disk or tape.\n"); break;
        case EISDIR: printf(" fd refers to a directory.\n"); break;
	}
}
void printWaitpidError(int error)
{
	switch (errno)
	{
		case ECHILD: 
		printf("(for wait()) The calling process does not have any unwaited-for children.\n"); 
		printf("(for waitpid() or waitid()) The process specified by pid (waitpid()) or idtype and id (waitid()) does not exist or is not a child of the calling process.  (This can happen for one's own child if the action for SIGCHLD is set to SIG_IGN.  See also the Linux Notes section about threads.)\n"); break;
		case EINTR:  printf("WNOHANG was not set and an unblocked signal or a SIGCHLD was caught; see signal(7).\n"); break;
		case EINVAL: printf("The options argument was invalid.\n"); break;
	}
}

void printSetenvError(int error)
{
	switch (errno)
	{
		case EINVAL: printf("Error setting environment var: \"name is NULL, points to a string of length 0, or contains an '=' character.\"\n");
		break;
		case ENOMEM: printf("Error setting environment var: \"Insufficient memory to add a new variable to the environment.\"\n");
		break;
	}
}

void printForkError(int error)
{
	switch (errno)
	{
		case EAGAIN:  
		printf("A system-imposed limit on the number of threads was encountered.\n");
		printf("The caller is operating under the SCHED_DEADLINE scheduling policy and does not have the reset-on-fork flag set.  See sched(7).\n"); break;
		case ENOMEM:
		printf("fork() failed to allocate the necessary kernel structures because memory is tight.\n");
		printf("An attempt was made to create a child process in a PID namespace whose \"init\" process has terminated.  See pid_namespaces(7).\n"); break;
		case ENOSYS: printf("fork() is not supported on this platform (for example, hardware without a Memory-Management Unit).\n"); break;
		//case ERESTARTNOINTR: printf("(since Linux 2.6.17) System call was interrupted by a signal and will be restarted.  (This can be seen only during a trace.)\n"); break;
	}
}

void printPipeError(int error)
{
	switch (error)
	{
		case EFAULT: printf("pipefd is not valid.\n");
		break;
        case EINVAL: printf("(pipe2()) Invalid value in flags.\n");
        break;
        case EMFILE: printf("The per-process limit on the number of open file descriptors has been reached.\n");
        break;
        case ENFILE: 
        printf("The system-wide limit on the total number of open files has been reached.\n");
        printf("The user hard limit on memory that can be allocated for pipes has been reached and the caller is not privileged; see pipe(7).\n");
        break;
	}
}

void printExecError(int error)
{
	switch (error)
	{
		case E2BIG:
		  printf("The total number of bytes in the environment (envp) and argument list (argv) is too large.\n");
		  break;
       case EACCES:
		  printf("Search permission is denied on a component of the path prefix of filename or the name of a script interpreter.  (See also path_resolution(7).)\n");
		  printf("The file or a script interpreter is not a regular file.\n");
		  printf("Execute permission is denied for the file or a script or ELF interpreter.\n");
		  printf("The filesystem is mounted noexec.\n");
		  break;
       case EAGAIN:
		  printf("Having changed its real UID using one of the set*uid() calls, the caller was—and is now still—above its RLIMIT_NPROC resource  limit  (see  setrlimit(2)).   For  a  more detailed explanation of this error, see NOTES.\n");
		  break;
       case EFAULT:
		  printf("filename or one of the pointers in the vectors argv or envp points outside your accessible address space.\n");
		  break;
       case EINVAL:
		  printf("An ELF executable had more than one PT_INTERP segment (i.e., tried to name more than one interpreter).\n");
		  break;
       case EIO:
		  printf("An I/O error occurred.\n");
		  break;
       case EISDIR:
		  printf("An ELF interpreter was a directory.\n");
		  break;
       case ELIBBAD:
		  printf("An ELF interpreter was not in a recognized format.\n");
		  break;
       case ELOOP:
       	printf("Too many symbolic links were encountered in resolving filename or the name of a script or ELF interpreter.\n");
		  printf("The  maximum  recursion  limit was reached during recursive script interpretation (see \"Interpreter scripts\", above).  Before Linux 3.8, the error produced for this case was ENOEXEC.\n");
		  break;
       case EMFILE:
		  printf("The per-process limit on the number of open file descriptors has been reached.\n");
		  break;
       case ENAMETOOLONG:
		  printf("filename is too long.\n");
		  break;
       case ENFILE:
		  printf("The system-wide limit on the total number of open files has been reached.\n");
		  break;
       case ENOENT:
		  printf("The file filename or a script or ELF interpreter does not exist, or a shared library needed for the file or interpreter cannot be found.\n");
		  break;
       case ENOEXEC:
		  printf("An executable is not in a recognized format, is for the wrong architecture, or has some other format error that means it cannot be executed.\n");
		  break;
       case ENOMEM:
		  printf("Insufficient kernel memory was available.\n");
		  break;
       case ENOTDIR:
		  printf("A component of the path prefix of filename or a script or ELF interpreter is not a directory.\n");
		  break;
       case EPERM:
		  printf("The filesystem is mounted nosuid, the user is not the superuser, and the file has the set-user-ID or set-group-ID bit set.\n");
		  printf("The process is being traced, the user is not the superuser and the file has the set-user-ID or set-group-ID bit set.\n");
		  printf("A \"capability-dumb\" applications would not obtain the full set of permitted capabilities granted by the executable file.  See capabilities(7).\n");
		  break;
       case ETXTBSY:
		  printf("The specified executable was open for writing by one or more processes.\n");
		  break;
	}
}
