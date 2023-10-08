#ifndef THREADS_ARC_H
#define THREADS_ARC_H

#include "threads/synch.h"

#define arc_data(ARC, STRUCT, MEMBER) ((STRUCT*)((uint8_t*)(ARC)-offsetof(STRUCT, MEMBER)))

struct arc {
  size_t ref_count;
  void (*destroy)(struct arc*);
};

static inline void arc_init(struct arc* arc, void (*destroy)(struct arc*)) {
  arc->ref_count = 1;
  arc->destroy = destroy;
}

static inline size_t arc_inc_ref(struct arc* arc) {
  return __atomic_add_fetch(&arc->ref_count, 1, __ATOMIC_RELAXED);
}

static inline size_t arc_dec_ref(struct arc* arc) {
  size_t cnt = __atomic_sub_fetch(&arc->ref_count, 1, __ATOMIC_RELEASE);
  if (cnt == 0) {
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    arc->destroy(arc);
  }
  return cnt;
}

#endif
