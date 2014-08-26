#include <execinfo.h>
#include <cxxabi.h>
#include <signal.h>
#include <unistd.h>

#include <string>
#include <cstdio>
#include <cstring>

#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "stacktracer.h"

#define MAX_TRACE_LEVELS 256

extern char* program_invocation_name;

namespace {

class AutoDescriptor {
public:
    AutoDescriptor(int fd = -1): fd(fd) {}
    ~AutoDescriptor() { close(); }

    int get() const { return fd; }
    int release() {
        int ret = fd;
        fd = -1;
        return ret;
    }

    void close() {
        while (fd >= 0) {
            if (!::close(fd)) {
                fd = -1;
            }
        }
    }

    AutoDescriptor& operator =(int newFd) {
        if (fd == newFd) {
            return *this;
        }

        close();
        fd = newFd;
    }

private:
    int fd;
};

int addr2linePid;
int addr2lineInFd = -1;
int addr2lineOutFd = -1;
FILE* addr2lineIn;
FILE* addr2lineOut;

void initAddr2line() __attribute__((constructor));
void initAddr2line()
{
    constexpr int IN = 0;
    constexpr int OUT = 1;

    AutoDescriptor addrPipe[2];
    AutoDescriptor linePipe[2];

    if (pipe((int*)addrPipe)
            || pipe((int*)linePipe)) {
        abort();
    }

    switch (addr2linePid = fork()) {
    case -1:
        abort();
    case 0:
        {
            if (dup2(addrPipe[IN].get(), 0)
                    || dup2(linePipe[OUT].get(), 1)) {
                abort();
            }

            char addr2lineCmd[] = "addr2line";
            char addr2lineArg[] = "-Capfe";
            char* argv[] {
                addr2lineCmd, 
                addr2lineArg,
                program_invocation_name
            };
            execve(argv[0], argv, NULL);
            abort();
        }
    default:
        addr2lineInFd = addrPipe[IN].release();
        addr2lineIn = fdopen(addr2lineInFd, "r");
        addr2lineOutFd = linePipe[OUT].release();
        addr2lineOut = fdopen(addr2lineOutFd, "w");
        break;
    }
}

std::string demangle(const char* symbol) {
    size_t size;
    int status;
    char temp[1024];
    char* demangled;

    //first, try to demangle a c++ name
    if (sscanf(symbol, "%*[^(]%*[^_]%127[^)+]", temp) == 1) {
        if (NULL != (demangled = abi::__cxa_demangle(temp, NULL, &size, &status))) {
            std::string result(demangled);
            free(demangled);
            return result;
        }
    }

    //if that didn't work, try to get a regular c symbol
    if (1 == sscanf(symbol, "%127s", temp)) {
        return temp;
    }

    //if all else fails, just return the symbol
    return symbol;
}

std::vector<void*> get_stack_trace_addrs()
{
    std::vector<void*> addrs(MAX_TRACE_LEVELS);

    size_t size = backtrace(&addrs[0], addrs.size());
    addrs.resize(size);

    return addrs;
}

bool is_own_symbol(const char* symbol) {
    const char* sym = symbol;
    const char* prog = program_invocation_name;

    while (*prog) {
        if (!*sym || *prog != *sym) {
            return false;
        }
        ++sym;
        ++prog;
    }

    return *sym == '(';
}

std::string addr2line(void* addr) {
    fprintf(addr2lineIn, "%p\n", addr);

    char* line_ptr = nullptr;
    size_t size = 0;
    if (getline(&line_ptr, &size, addr2lineOut) < 0) {
        return "<addr2line failed>";
    }

    std::unique_ptr<char, void(*)(void*)> line(line_ptr, free);
    std::string ret(line_ptr);

    size_t lastChar = ret.find_last_not_of("\r\n");
    return ret.substr(0, lastChar + 1);
}

std::vector<StackFrame> get_trace_symbols(const std::vector<void*>& addrs)
{
    std::unique_ptr<char*[], void(*)(void*)>
            symbols(backtrace_symbols(&addrs[0], addrs.size()), free);

    std::vector<StackFrame> frames;
    for (size_t i = 0; i < addrs.size(); ++i) {
        frames.push_back({ addrs[i],
                           is_own_symbol(symbols[i]) ? addr2line(addrs[i])
                                                     : demangle(symbols[i]) });
    }

    return frames;
}

void fix_stack_trace(ucontext_t* context,
                     std::vector<void*>& stackTrace)
{
    void* caller_address;
    /* Get the address at the time the signal was raised */
#if defined(__i386__) // gcc specific
    caller_address = (void*)context->uc_mcontext.gregs[REG_EIP]; // EIP: x86 specific
#elif defined(__x86_64__) // gcc specific
    caller_address = (void*)context->uc_mcontext.gregs[REG_RIP]; // RIP: x86_64 specific
#else
#error Unsupported architecture. // TODO: Add support for other arch.
#endif

    stackTrace[2] = caller_address;
}
 
std::string get_signal_trace_string(ucontext_t* context)
{
    std::vector<void*> addrs = get_stack_trace_addrs();
    fix_stack_trace(context, addrs);
    std::vector<StackFrame> frames = get_trace_symbols(addrs);

    return get_stack_trace_string(frames);
}

struct sigaction DEFAULT_SIGNAL_HANDLERS[32] = {};

void signal_handler(int sigNum,
                    siginfo_t* info,
                    void* context)
{
    const char* sigName = strsignal(sigNum);
    std::cerr << "caught signal: " << sigName << "\n"
              << "stack trace:\n"
              << get_signal_trace_string((ucontext_t*)context);

    if (DEFAULT_SIGNAL_HANDLERS[sigNum].sa_sigaction) {
        DEFAULT_SIGNAL_HANDLERS[sigNum].sa_sigaction(sigNum, info, context);
    }
    if (DEFAULT_SIGNAL_HANDLERS[sigNum].sa_handler) {
        DEFAULT_SIGNAL_HANDLERS[sigNum].sa_handler(sigNum);
    }

    abort();
}

void init_signal_handlers() __attribute__((constructor));
void init_signal_handlers()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    for (int sig: { SIGINT, SIGTERM, SIGHUP, SIGSEGV, SIGFPE }) {
        sigaction(sig, &sa, &DEFAULT_SIGNAL_HANDLERS[sig]);
    }
}

} // namespace

extern "C" {

std::vector<StackFrame> get_stack_trace()
{
    constexpr size_t ENTRIES_TO_SKIP = 0;

    std::vector<void*> addrs = get_stack_trace_addrs();
    std::copy(addrs.begin() + ENTRIES_TO_SKIP, addrs.end(), addrs.begin());
    return get_trace_symbols(addrs);
}

std::string get_stack_trace_string(const std::vector<StackFrame>& frames) {
    std::stringstream ss;

    for (const StackFrame& frame: frames) {
        ss << frame.name << std::endl;
    }

    return ss.str();
}

} // extern "C"

namespace std {

#define DECLARE_EXCEPTION(Name) \
    Name::Name(const std::string& what): _M_msg(what + "\n" + get_stack_trace_string(get_stack_trace())) {}

DECLARE_EXCEPTION(logic_error)
DECLARE_EXCEPTION(runtime_error)

} // namespace std

