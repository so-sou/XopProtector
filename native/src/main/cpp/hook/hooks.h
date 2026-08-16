#pragma once

namespace protector::hook {

/** Idempotent bytehook_init — safe from constructor and init_app. */
void ensure_bytehook();

/** ART DefineClass/LoadClass + mmap/execve hooks. */
void install_hooks();

} // namespace protector::hook
