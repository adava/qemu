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
      && lhs.op == rhs.op
      && lhs.size == rhs.size
      && lhs.op1 == rhs.op1
      && lhs.op1_type == rhs.op1_type
      && lhs.op2 == rhs.op2
      && lhs.op2_type == rhs.op2_type
      && lhs.dest == rhs.dest
      && lhs.dest_type == rhs.dest_type;
}

}
