#ifndef NEXUSLAB_NAPI_HOOK_H
#define NEXUSLAB_NAPI_HOOK_H

namespace nexuslab_napi {

void InstallNapiHooks();
void ShutdownNapiHooks();
int HookedFunctionCount();

}

#endif
