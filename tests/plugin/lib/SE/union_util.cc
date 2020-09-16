#include "union_util.h"

namespace __taint {

/**
 * Initialize allocator memory,
 * begin: first usable byte
 * end: first unusable byte
 */

option::option(bool isa, dfsan_label l) {
  this->isa = isa;
  this->content = l;
}

option some_dfsan_label(dfsan_label x) {
  return option(true, x);
}

option none() {
  return option(false, 0);
}

bool
option::operator==(option rhs) {
    if (isa == false) {
          return rhs.isa == false;
            }
      return rhs.isa != false && content == rhs.content;
}

bool
option::operator!=(option rhs) {
  return !(*this == rhs);
}

dfsan_label
option::operator*() {
    return this->content;
}

bool
operator==(const dfsan_label_info& lhs, const dfsan_label_info& rhs) {
  return lhs.l1 == rhs.l1
      && lhs.l2 == rhs.l2
      && lhs.instruction.op == rhs.instruction.op
      && lhs.instruction.size == rhs.instruction.size
      && lhs.instruction.op1 == rhs.instruction.op1
      && lhs.instruction.op1_type == rhs.instruction.op1_type
      && lhs.instruction.op2 == rhs.instruction.op2
      && lhs.instruction.op2_type == rhs.instruction.op2_type
      && lhs.instruction.dest == rhs.instruction.dest
      && lhs.instruction.dest_type == rhs.instruction.dest_type;
}

}
