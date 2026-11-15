#ifndef NEXUSLAB_INLINE_HOOK_H
#define NEXUSLAB_INLINE_HOOK_H

#include <cstddef>

namespace nexuslab_inline {

bool Install(void* target, void* replacement, void** trampolineOut);
void RemoveAll();

}

#endif
