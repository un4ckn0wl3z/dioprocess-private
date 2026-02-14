#pragma once

#include <intrin.h>

namespace hv {

// spin lock with exponential backoff to reduce bus contention
struct spin_lock {
  void initialize() {
    lock = 0;
  }

  void acquire() {
    // fast path: try to acquire immediately
    if (0 == _InterlockedCompareExchange(&lock, 1, 0))
      return;

    // slow path: exponential backoff
    unsigned backoff = 1;
    constexpr unsigned max_backoff = 64;

    while (1 == _InterlockedCompareExchange(&lock, 1, 0)) {
      // spin-wait with increasing pause count to reduce bus traffic
      for (unsigned i = 0; i < backoff; ++i)
        _mm_pause();

      if (backoff < max_backoff)
        backoff <<= 1;
    }
  }

  void release() {
    // use a store-release barrier for correct ordering
    _InterlockedExchange(&lock, 0);
  }

  volatile long lock;
};

class scoped_spin_lock {
public:
  scoped_spin_lock(spin_lock& lock)
      : lock_(lock) {
    lock.acquire();
  }

  ~scoped_spin_lock() {
    lock_.release();
  }

  // no copying
  scoped_spin_lock(scoped_spin_lock const&) = delete;
  scoped_spin_lock& operator=(scoped_spin_lock const&) = delete;

private:
  spin_lock& lock_;
};

} // namespace hv

