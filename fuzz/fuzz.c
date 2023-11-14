// SanitizerCoverage-based coverage collection code for libcoverage.
// Copy+paste this code into the JavaScript shell binary.

//
// BEGIN FUZZING CODE
//
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


#define REPRL_CRFD 100
#define REPRL_CWFD 101
#define REPRL_DRFD 102
#define REPRL_DWFD 103

#define SHM_SIZE 0x100000
#define MAX_EDGES ((SHM_SIZE - 4) * 8)

#define CHECK(cond) if (!(cond)) { printf("\"" #cond "\" failed\n"); _exit(-1); }

struct shmem_data {
    uint32_t num_edges;
    unsigned char edges[];
};

struct shmem_data* __shmem;
uint32_t *__edges_start, *__edges_stop;

void __sanitizer_cov_reset_edgeguards() {
    uint64_t N = 0;
    for (uint32_t *x = __edges_start; x < __edges_stop && N < MAX_EDGES; x++)
        *x = ++N;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    // Avoid duplicate initialization
    if (start == stop || *start)
        return;

    if (__edges_start != NULL || __edges_stop != NULL) {
        printf("Coverage instrumentation is only supported for a single module\n");
        _exit(-1);
    }

    __edges_start = start;
    __edges_stop = stop;

    // Map the shared memory region
    const char* shm_key = getenv("SHM_ID");
    if (!shm_key) {
        puts("[COV] no shared memory bitmap available, skipping");
        __shmem = (struct shmem_data*) malloc(SHM_SIZE);
    } else {
        int fd = shm_open(shm_key, O_RDWR, S_IREAD | S_IWRITE);
        if (fd <= -1) {
            printf("Failed to open shared memory region: %s\n", strerror(errno));
            _exit(-1);
        }

        __shmem = (struct shmem_data*) mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (__shmem == MAP_FAILED) {
            printf("Failed to mmap shared memory region\n");
            _exit(-1);
        }
    }

    __sanitizer_cov_reset_edgeguards();

    __shmem->num_edges = stop - start;
    printf("[COV] edge counters initialized. Shared memory: %s with %u edges\n", shm_key, __shmem->num_edges);
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    // There's a small race condition here: if this function executes in two threads for the same
    // edge at the same time, the first thread might disable the edge (by setting the guard to zero)
    // before the second thread fetches the guard value (and thus the index). However, our
    // instrumentation ignores the first edge (see libcoverage.c) and so the race is unproblematic.
    uint32_t index = *guard;
    // If this function is called before coverage instrumentation is properly initialized we want to return early.
    if (!index) return;
    __shmem->edges[index / 8] |= 1 << (index % 8);
    *guard = 0;
}

//
// END FUZZING CODE
//


void write_to_file(char *data);

#include "jsi.h"
static Jsi_CmdProcDecl(fuzzilli);

int main(int argc, char **argv)
{   
    /*
    Jsi_Interp *interp = Jsi_InterpNew(NULL);
    Jsi_CommandCreate(interp, "fuzzilli", fuzzilli, NULL);
    //Jsi_InterpSetErrorHandler(interp, callback);
    

    Jsi_EvalString(interp, "fuzzilli('FUZZILLI_CRASH', 2)", 0x10);  //JSI_EVAL_RETURN
    exit(0);
    */

	char helo[] = "HELO";
	if ((write(REPRL_CWFD, helo, 4) != 4) || (read(REPRL_CRFD, helo, 4) != 4)) {
		write_to_file("Error writing or reading HELO\n");
		_exit(-1);
	}
	if (memcmp(helo, "HELO", 4) != 0) {
		write_to_file("Invalid response from parent\n");
		_exit(-1);
	}

    
	while (1) {
		unsigned action = 0;
		ssize_t nread = read(REPRL_CRFD, &action, 4);
		if (nread != 4 || action != 0x63657865) { // 'exec'
			write_to_file("Unknown action: %x\n");
			_exit(-1);
		}

		size_t script_size = 0;
		read(REPRL_CRFD, &script_size, 8);

        //We are going to append good() to the end of the script

		char* buffer = malloc(script_size+1);

        if (script_size > 0) {
            ssize_t rv = read(REPRL_DRFD, buffer, script_size);
            if (rv <= 0) {
                fprintf(stderr, "Failed to load script\n");
                write_to_file("Failed to load script\n");
                _exit(-1);
            }
        }
		buffer[script_size] = '\0';

        Jsi_InterpOpts opts = {.argc=argc, .argv=argv, .no_interactive=0, .auto_delete=1,};
        Jsi_Interp *interp = Jsi_InterpNew(&opts);
		Jsi_CommandCreate(interp, "fuzzilli", fuzzilli, NULL);
		Jsi_RC rc = Jsi_EvalString(interp, buffer, 0);

        int ret_value = (int)rc;

		fflush(stdout);
		fflush(stderr);
		int status = (ret_value & 0xff) << 8;
		if (write(REPRL_CWFD, &status, 4) != 4) {
			write_to_file("Error writing return value over REPRL_CWFD\n");
		}

        free(buffer);
		__sanitizer_cov_reset_edgeguards();
	}

	return 0;
}


/**
 * Executes the fuzzilli fuzzer on the given input.
 */
static Jsi_CmdProcDecl(fuzzilli) {

    //Get first arg to a string
    const char* str = Jsi_ValueArrayIndexToStr(interp, args, 0, NULL);

     if (!str) {
        write_to_file("js_fuzzilli NO CMD\n");
        return 0;
    }
    if (!strcmp(str, "FUZZILLI_CRASH")) {
        
        write_to_file("js_fuzzilli CRASH\n");

        //Get the second arg to an int
        const char *arg_str = Jsi_ValueArrayIndexToStr(interp, args, 1, NULL);
        int arg = atoi(arg_str);

        switch (arg) {
            case 0:
                // check crash
                *((uint32_t *) 0x41414141) = 1337;
                break;
            case 1: {
                // check ASAN
                char *data = malloc(64);
                free(data);
                data[0]++;
                break;
            }
        }
    } else if (!strcmp(str, "FUZZILLI_PRINT")) {
        // get next argument off the stack to print
        const char* print_str = Jsi_ValueArrayIndexToStr(interp, args, 1, NULL);


        write_to_file("js_fuzzilli PRINT %s\n");
        write_to_file((char*)print_str);
        FILE* fzliout = fdopen(REPRL_DWFD, "w");
        if (!fzliout) {
            printf("Fuzzer output channel not available, printing to stdout instead\n");
            fzliout = stdout;
        }
        if (print_str) {
            fprintf(fzliout, "%s\n", print_str);
        }
        fflush(fzliout);
    }
    return 0;
}

//Appends data to /tmp/fuzzilli
void write_to_file(char *data){
    FILE *f = fopen("/tmp/fuzzilli", "a");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    fprintf(f, "%s\n", data);

    fclose(f);
}
