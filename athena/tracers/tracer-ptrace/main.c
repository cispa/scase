#define _GNU_SOURCE
#include <memory.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "PTEditor/ptedit_header.h"

#include "../common/elf.h"

//#define DEBUGMODE

#define PAGESIZE 4096

#define TRACE_FILE_HEADER "virt_addr;rip\n"

typedef struct {
    void* virt_addr;
    void* section_base_addr;
} monitor_page_t;

typedef struct {
    void* virt_addr;
    void* rip;
} trace_entry_t;

monitor_page_t* exec_pages_to_monitor;
size_t exec_pages_to_monitor_length;
size_t exec_pages_to_monitor_reserved;

monitor_page_t* data_pages_to_monitor;
size_t data_pages_to_monitor_length;
size_t data_pages_to_monitor_reserved;

char* tracee_path;
uint64_t tracee_binary_base;

uint64_t breakpoint_addr;
long breakpoint_original_data; 

trace_entry_t* data_flow_trace;
size_t data_flow_trace_length;
size_t data_flow_trace_alloc_size;

trace_entry_t* control_flow_trace;
size_t control_flow_trace_length;
size_t control_flow_trace_alloc_size;

FILE* fd_control_flow_trace;
FILE* fd_data_flow_trace;

void error_exit(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, strerror(errno));  // Print error message with errno

  exit(EXIT_FAILURE);
}

size_t append_to_control_flowtrace(trace_entry_t entry) {
  // lazy allocation
  if (control_flow_trace == NULL) {
    control_flow_trace_alloc_size = 32;
    control_flow_trace = malloc(control_flow_trace_alloc_size * sizeof(trace_entry_t));
  }

  // check if we need to resize
  if (control_flow_trace_length == control_flow_trace_alloc_size) {
    control_flow_trace_alloc_size *= 2;
    control_flow_trace = realloc(control_flow_trace, 
        control_flow_trace_alloc_size * sizeof(trace_entry_t));
  }

  // add and increment length
  control_flow_trace[control_flow_trace_length] = entry;
  control_flow_trace_length++;
}

trace_entry_t pop_from_control_flowtrace() {
  if (control_flow_trace_length == 0) {
    error_exit("Tried popping from empty CF trace.");
  }
  trace_entry_t last_entry = control_flow_trace[control_flow_trace_length-1];
  control_flow_trace_length--;
  return last_entry;
}

trace_entry_t peak_from_control_flowtrace() {
  if (control_flow_trace_length == 0) {
    error_exit("Tried peaking from empty CF trace.");
  }
  return control_flow_trace[control_flow_trace_length-1];
}

trace_entry_t pick_from_control_flowtrace(int idx) {
  if (control_flow_trace_length < idx) {
    error_exit("Tried peaking from empty CF trace.");
  }
  return control_flow_trace[control_flow_trace_length-idx-1];
}

size_t append_to_data_flowtrace(trace_entry_t entry) {
  // lazy allocation
  if (data_flow_trace == NULL) {
    data_flow_trace_alloc_size = 32;
    data_flow_trace = malloc(data_flow_trace_alloc_size * sizeof(trace_entry_t));
  }

  // check if we need to resize
  if (data_flow_trace_length == data_flow_trace_alloc_size) {
    data_flow_trace_alloc_size *= 2;
    data_flow_trace = realloc(data_flow_trace, 
        data_flow_trace_alloc_size * sizeof(trace_entry_t));
  }

  // add and increment length
  data_flow_trace[data_flow_trace_length] = entry;
  data_flow_trace_length++;
}

// if any of these substrings occur in a memory section, we do not monitor it
const char* libraries_to_ignore[] = {
    //"x86_64-linux-gnu", 
    "ld-linux",  // TODO: this enables tracing of libc
    NULL};


int ends_with(const char *str, const char *substr) {
  size_t str_len = strlen(str);
  size_t substr_len = strlen(substr);

  // If substr is longer it can't be at the end
  if (str_len < substr_len) {
    return 0;
  }

  // check for match at the end
  return strcmp(str + str_len - substr_len, substr) == 0;
}

// careful we do not allocate a new string here and just calculate the offset
const char* extract_filename(const char* filepath) {
  // get the last '/'
  const char* filename = strrchr(filepath, '/');
  if (filename == NULL) {
    return filepath;
  }
  // we return the substring after the last '/'
  return filename + 1;
}

// ============================================================================
// PTrace-based interface
// ============================================================================

int wait_for_process(pid_t pid) {
  int status;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status)) {
    // tracee exited 
    return 1;
   }
  return 0;
}

int step_process(pid_t pid) {
  int status;
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
    error_exit("ptrace(PTRACE_SINGLESTEP) failed");
  }
  return wait_for_process(pid);
}

void attach_to_process(pid_t pid) {
  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
  long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if (ret == -1) {
    error_exit("ptrace(PTRACE_ATTACH) failed");
  }
}

uint64_t read_rip(pid_t pid) {
  struct user_regs_struct regs;
  long ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  if (ret == -1) {
    error_exit("ptrace(PTRACE_GETREGS) failed");
  }
  return regs.rip;
}


void set_breakpoint(pid_t pid, uint64_t addr) {
  if (breakpoint_addr != 0) {
    error_exit("Breakpoint already active. We do not support more than one.");
  }
#ifdef DEBUGMODE
  printf("[*] Setting breakpoint at 0x%" PRIx64 "\n", addr);
#endif
  breakpoint_addr = addr;

  // read out the original bytes at the address
  breakpoint_original_data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
  if (breakpoint_original_data == -1) {
    error_exit("ptrace(PTRACE_PEEKTEXT) failed: reading original data");
  }
  // set breakpoint (inserting 0xCC | int3 opcode)
  long data_int3 = (breakpoint_original_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
  if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)data_int3) == -1) {
    error_exit("ptrace(PTRACE_POKETEXT) failed: setting breakpoint");
  }
}


void restore_from_breakpoint(pid_t pid) {
  if (breakpoint_addr == 0) {
    error_exit("No active breakpoint to restore.");
  }

  // make sure we are at the breakpoint address
  uint64_t current_addr = read_rip(pid);  
  // a breakpoint is hit at the address after the int3 opcode, hence -1
  if (current_addr - 1 != breakpoint_addr) {
    printf("current_addr: 0x%" PRIx64 "\n", current_addr);
    printf("breakpoint_addr: 0x%" PRIx64 "\n", breakpoint_addr);
    error_exit("Caught SIGTRAP but not at breakpoint address.");
  }

  // restore original data
  if (ptrace(PTRACE_POKETEXT, pid, (void*)breakpoint_addr, (void*)breakpoint_original_data) == -1) {
    error_exit("ptrace(PTRACE_POKETEXT) failed: restoring original data");
  }

  // unset the breakpoint addr for internal book keeping
  breakpoint_addr = 0;
}


void continue_until_breakpoint_hit(pid_t pid) {
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
    error_exit("ptrace(PTRACE_CONT) failed");
  }
  wait_for_process(pid);
  restore_from_breakpoint(pid);
}

void set_breakpoint_symbol(pid_t pid, const char* symbol_name) {
  uint64_t symbol_addr = lookup_elf_symbol(symbol_name);
  if (symbol_addr == -1) {
    printf("Tried looking up: %s\n", symbol_name);
    error_exit("Symbol not found");
  }
  if (tracee_binary_base == 0) {
    error_exit("Tracee binary base not set");
  }
  if (is_dynamically_linked_binary(tracee_path)) {
    set_breakpoint(pid, tracee_binary_base + symbol_addr);
  } else {
    set_breakpoint(pid, symbol_addr);
  }
}

// ============================================================================
// Page-Monitoring functions
// ============================================================================

void clear_monitor_pages() {
  exec_pages_to_monitor_length = 0;
  data_pages_to_monitor_length = 0;
}

void append_to_monitor_pages(monitor_page_t page, int is_exec_page) {
  monitor_page_t** pages_to_monitor;
  size_t* pages_to_monitor_length;
  size_t* pages_to_monitor_reserved;
  if (is_exec_page) {
    pages_to_monitor = &exec_pages_to_monitor;
    pages_to_monitor_length = &exec_pages_to_monitor_length;
    pages_to_monitor_reserved = &exec_pages_to_monitor_reserved;
  } else {
    pages_to_monitor = &data_pages_to_monitor;
    pages_to_monitor_length = &data_pages_to_monitor_length;
    pages_to_monitor_reserved = &data_pages_to_monitor_reserved;
  }

  if (*pages_to_monitor == NULL) {
    *pages_to_monitor_reserved = 32;
    *pages_to_monitor = malloc(*pages_to_monitor_reserved * sizeof(monitor_page_t));
  }
  if (*pages_to_monitor_reserved < *pages_to_monitor_length + 1) {
    *pages_to_monitor_reserved = *pages_to_monitor_reserved * 2;
    *pages_to_monitor = realloc(*pages_to_monitor,
        *pages_to_monitor_reserved * sizeof(monitor_page_t));
  }
  (*pages_to_monitor)[(*pages_to_monitor_length)++] = page;
}

void clear_all_access_bits(pid_t pid) {
  for (size_t i = 0; i < exec_pages_to_monitor_length; i++) {
#ifdef DEBUGMODE
    printf("unsetting A-bit for page %p\n", exec_pages_to_monitor[i].virt_addr);
#endif
    ptedit_pte_clear_bit(
        exec_pages_to_monitor[i].virt_addr,
        pid,
        PTEDIT_PAGE_BIT_ACCESSED);
  }

  for (size_t i = 0; i < data_pages_to_monitor_length; i++) {
#ifdef DEBUGMODE
    printf("unsetting A-bit for page %p\n", data_pages_to_monitor[i].virt_addr);
#endif
    ptedit_pte_clear_bit(
        data_pages_to_monitor[i].virt_addr,
        pid,
        PTEDIT_PAGE_BIT_ACCESSED);
  }
}

void check_accessed_pages(pid_t pid, monitor_page_t* pages_to_monitor, 
    size_t pages_to_monitor_length, FILE* file_memory_trace, int is_exec) {
  uint64_t rip = read_rip(pid);
  int access_counter = 0;  // count the number of accesses per step
  for (size_t i = 0; i < pages_to_monitor_length; i++) {
    if (ptedit_pte_get_bit(
        pages_to_monitor[i].virt_addr,
        pid,
        PTEDIT_PAGE_BIT_ACCESSED)) {
      // we got an access
      access_counter++;
      trace_entry_t new_entry = {
          .virt_addr = pages_to_monitor[i].virt_addr,
          .rip = (void*)rip
      };

      if (access_counter == 1) {
#ifdef DEBUGMODE
        printf("\nRIP: 0x%" PRIx64 "\n", rip);
#endif
      }
#ifdef DEBUGMODE
        printf("--> %" PRIx64 "\n", pages_to_monitor[i].virt_addr);
#endif

      if (access_counter > 1 && is_exec) {
        // if we hit this, we see two CF pages being accessed, 
        // which is the case when an instruction is executed which is split across
        // two pages. In this case, we ignore subsequent hits
        // TODO: test this
        trace_entry_t last_entry = peak_from_control_flowtrace();
        if (last_entry.virt_addr + 0x1000 != new_entry.virt_addr) {
          trace_entry_t sec_last_entry = pick_from_control_flowtrace(1);
          printf("Multi CF access which is not the result from a split-page instruction\n");
          printf("No idea what to do here. Ignoring for Now\n");
          printf("-----------------------------\n");
          printf("\nRIP: 0x%" PRIx64 " (access-count: %d)\n", rip, access_counter);
          printf("\nCur. page: 0x%" PRIx64 "\n", new_entry.virt_addr);
          printf("\nLast page: 0x%" PRIx64 "\n", last_entry.virt_addr);
          printf("\nSec Last page: 0x%" PRIx64 "\n", sec_last_entry.virt_addr);
          printf("-----------------------------\n");
          //exit(1);
        }
        // if we get here, we have a split-page instruction, hence we ignore the access
      } else {  // if (!first_access && is_exec)
        // default case

        // add to file
        uint64_t relative_addr = (uint64_t)pages_to_monitor[i].virt_addr 
            - (uint64_t)pages_to_monitor[i].section_base_addr;
        fprintf(file_memory_trace, 
            "0x%" PRIx64 ";0x%" PRIx64 "\n", 
                pages_to_monitor[i].virt_addr, 
                rip);
        if (is_exec) {
          //printf("adding 0x%" PRIx64 " to CF trace\n", (uint64_t)new_entry.virt_addr);
          append_to_control_flowtrace(new_entry);
        } else {
          //printf("adding 0x%" PRIx64 " to DF trace\n", (uint64_t)new_entry.virt_addr);
          append_to_data_flowtrace(new_entry);
        }
      } 

      // clear A-bit again
      ptedit_pte_clear_bit(
          pages_to_monitor[i].virt_addr,
          pid,
          PTEDIT_PAGE_BIT_ACCESSED);
    }  // if (ptedit_pte_get_bit(
  }  // for (size_t i = 0; i < pages_to_monitor_length; i++)
}

void check_accessed_exec_pages(pid_t pid) {
  check_accessed_pages(pid, exec_pages_to_monitor, exec_pages_to_monitor_length,
      fd_control_flow_trace, 1);
}

void check_accessed_data_pages(pid_t pid) {
  check_accessed_pages(pid, data_pages_to_monitor, data_pages_to_monitor_length,
      fd_data_flow_trace, 0);
}

void print_mappings(pid_t pid) {
  printf("====== Memory mappings of tracee ======\n\n");
  char cmd[256] = {0};
  snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", pid);
  int ret = system(cmd);
  if (ret) {
    error_exit("system() failed");
  }
  printf("\n=======================================\n\n");
}

int is_ignored_library(const char* pathname) {
  for (size_t i = 0; libraries_to_ignore[i] != NULL; i++) {
    if (strstr(pathname, libraries_to_ignore[i]) != NULL) {
      return 1;
    }
  }
  return 0;
}

// returns 1 on success, 0 on failure
int load_tracee_memory_maps(pid_t pid, const char* tracee_name) {
  char fname[256] = {0};
  snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
  FILE *maps_file = fopen(fname, "r");
  if (maps_file == NULL) {
    error_exit("fopen failed");
  }

  int found_tracee_mappings = 0;
  char line[256];
  while (fgets(line, sizeof(line), maps_file)) {
    // Example line format:
    // 00400000-00452000 r-xp 00000000 08:01 123456  /usr/bin/cat

    unsigned long start, end;
    char perms[5];  // To store permission string like "r-xp"
    char pathname[256] = {0};
    
    // Parse the start and end addresses and permissions
    int parsed_fields = sscanf(
        line, 
        "%lx-%lx %4s %*s %*s %*s %255s", 
        &start, &end, perms, pathname);
    if (parsed_fields > 3) {

      if (found_tracee_mappings == 0 && ends_with(pathname, tracee_name)) {
#ifdef DEBUGMODE
        print_mappings(pid);
#endif
        printf("[+] Found tracee memory maps\n");
        printf("[+] Identified first binary section: %s\n", pathname);
        tracee_binary_base = start;
        printf("[+] Identified binary base: 0x%lx\n", tracee_binary_base);
        found_tracee_mappings = 1;
      }
      if (is_ignored_library(pathname)) {
        continue;
      }

      // Check if the page has executable permissions (check 'x' in perms)
      int is_exec_page = strchr(perms, 'x') != NULL;

      //printf("Executable pages: %lx-%lx -> %s\n", start, end, pathname);
      for (unsigned long addr = start; addr <= end; addr += PAGESIZE) {
        monitor_page_t page = { 
            .virt_addr = (void*)addr,
            .section_base_addr = (void*)start};
        append_to_monitor_pages(page, is_exec_page);
      }
    }
  }
  fclose(maps_file);
  if (!found_tracee_mappings) {
    clear_monitor_pages();
  }
  return found_tracee_mappings;
}

void open_log_files() {
  fd_control_flow_trace = fopen("cftrace.csv", "w");
  if (fd_control_flow_trace == NULL) {
    error_exit("fopen() on 'cftrace.csv' failed");
  }
  fwrite(TRACE_FILE_HEADER, 1, strlen(TRACE_FILE_HEADER), fd_control_flow_trace);

  fd_data_flow_trace = fopen("dftrace.csv", "w");
  if (fd_data_flow_trace == NULL) {
    error_exit("fopen() on 'dftrace.csv' failed");
  }
  fwrite(TRACE_FILE_HEADER, 1, strlen(TRACE_FILE_HEADER), fd_data_flow_trace);
}

void cleanup() {
  fclose(fd_control_flow_trace);
  fclose(fd_data_flow_trace);
  ptedit_cleanup();
}


int main(int argc, char* argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <TARGET_FUNC> <program> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  const char* target_func = argv[1];
  tracee_path = argv[2];


  pid_t pid;
  pid = fork();
  if (pid == 0) {
      // child process
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      int res = execvp(tracee_path, argv + 2);
      assert(res == 0 && "execvp failed");
      if (res != 0) {
        error_exit("execvp failed");
      }

  }
  // parent process

  attach_to_process(pid);
  wait_for_process(pid);

  // we assume that argv[2] is the path to the ELF file of the tracee
  const char* tracee_name = extract_filename(tracee_path);


  // step 1) we single-step the tracee until the new memory maps are loaded
  // (this is necessary as directly after the fork() the memory maps are not 
  //  loaded yet as the tracee is not yet started and its ELF file is not 
  //  yet loaded)
  int tracee_memory_is_initialized = 0;
  while (tracee_memory_is_initialized == 0) {
    int finished = step_process(pid);
    if (finished) {
      error_exit("tracee exited before memory maps were loaded."
        "Probably a bug in the tracer!?");
    }
    tracee_memory_is_initialized = load_tracee_memory_maps(pid, tracee_name);
  }

  //
  // step 2) we parse the symbol table of the tracee ELF and extract the locations
  //
  load_elf_symbols(tracee_path);

  //
  // step 3) we set a breakpoint at the target function and execute to it
  //

  // for dynamically linked binaries, we need to add the base address to 
  // the symbol address; else we must use the symbol address directly
  uint64_t target_func_addr;
  if (is_dynamically_linked_binary(tracee_path)) {
    target_func_addr = tracee_binary_base + lookup_elf_symbol(target_func);
  } else {
    target_func_addr = lookup_elf_symbol(target_func);
  }
  printf("[+] Starting trace on symbol %s @ 0x%lx\n", target_func,
      target_func_addr);
  set_breakpoint_symbol(pid, target_func);
  continue_until_breakpoint_hit(pid);

  //
  // step 4) we update the memory maps to make sure we also include libraries 
  //  which were not loaded previously
  printf("[+] Updating tracee maps, in case of lazy loaded libraries\n");
  load_tracee_memory_maps(pid, tracee_name);


  if (ptedit_init()) {
    error_exit("ptedit_init failed");
  }

  //
  // step 5) start monitoring the pages
  //
  clear_all_access_bits(pid);

  open_log_files();
  while (1) {
    int finished = step_process(pid);
    if (finished) break;
//#ifdef DEBUGMODE
//    printf("DBG: Stepping @ 0x%lx\n", read_rip(pid));
//#endif
    check_accessed_exec_pages(pid);
    check_accessed_data_pages(pid);
  }

  cleanup();
  exit(EXIT_SUCCESS);
}
