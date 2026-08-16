#include "common/runtime_state.h"
#include "vm/pvm2_format.h"

namespace protector {

CodeItem::CodeItem() = default;
CodeItem::~CodeItem() = default;

RuntimeState& runtime_state() {
    static RuntimeState state;
    return state;
}

} // namespace protector
