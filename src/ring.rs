//! Fixed-capacity ring buffer for metric history.
//!
//! A monitor that keeps history in a `Vec` and pushes forever is a memory leak
//! with extra steps. This buffer allocates its full capacity once at
//! construction and never allocates again: pushing into a full buffer overwrites
//! the oldest entry.
//!
//! Implementation notes:
//!
//! * Backing storage is a `Vec<Option<T>>` of exactly `capacity` slots, plus a
//!   write cursor and a length. Overwriting is a single indexed store, so push
//!   is O(1) with no reallocation, no memmove and no branch on capacity growth.
//!
//! * Why not `VecDeque`? A `VecDeque` grows when you push past capacity unless
//!   you also pop, so the bound would depend on every caller remembering to pop
//!   first. Enforcing the bound in the type means it cannot be forgotten. The
//!   cost is one extra `Option` discriminant per slot, which is nothing next to
//!   the guarantee.
//!
//! * `iter_chrono` yields oldest-to-newest regardless of where the cursor sits,
//!   so callers never deal with the wrap point.

#[derive(Debug, Clone)]
pub struct Ring<T> {
    slots: Vec<Option<T>>,
    /// Index the next push will write to.
    head: usize,
    /// Number of live items, saturating at capacity.
    len: usize,
    /// Total pushes ever, including overwritten ones. Useful for diagnostics.
    pushed: u64,
}

impl<T> Ring<T> {
    /// Capacity is clamped to at least 1; a zero-capacity ring can hold nothing
    /// and every push would be a silent discard.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || None);
        Ring { slots, head: 0, len: 0, pushed: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn is_full(&self) -> bool {
        self.len == self.slots.len()
    }
    pub fn total_pushed(&self) -> u64 {
        self.pushed
    }

    /// Push, overwriting the oldest entry if full. Returns the evicted value.
    pub fn push(&mut self, v: T) -> Option<T> {
        let cap = self.slots.len();
        let evicted = self.slots[self.head].replace(v);
        self.head = (self.head + 1) % cap;
        if self.len < cap {
            self.len += 1;
        }
        self.pushed += 1;
        evicted
    }

    /// Index 0 is the oldest live item.
    fn phys(&self, logical: usize) -> usize {
        let cap = self.slots.len();
        // When full, the oldest sits at head; otherwise the buffer starts at 0.
        let start = if self.len == cap { self.head } else { 0 };
        (start + logical) % cap
    }

    pub fn get(&self, logical: usize) -> Option<&T> {
        if logical >= self.len {
            return None;
        }
        self.slots[self.phys(logical)].as_ref()
    }

    /// Most recently pushed item.
    pub fn newest(&self) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        let cap = self.slots.len();
        self.slots[(self.head + cap - 1) % cap].as_ref()
    }

    pub fn oldest(&self) -> Option<&T> {
        self.get(0)
    }

    /// Oldest to newest.
    pub fn iter_chrono(&self) -> impl Iterator<Item = &T> {
        (0..self.len).filter_map(move |i| self.get(i))
    }

    pub fn clear(&mut self) {
        for s in self.slots.iter_mut() {
            *s = None;
        }
        self.head = 0;
        self.len = 0;
    }
}
