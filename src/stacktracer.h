#ifndef STACKTRACER_H
#define STACKTRACER_H

struct StackFrame
{
    void* address;
    std::string name;
};

extern "C" {

std::vector<StackFrame> get_stack_trace();
std::string get_stack_trace_string(const std::vector<StackFrame>& frames);

} // extern "C"

#endif /* STACKTRACER_H */

