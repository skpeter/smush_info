//! Results-menu replay save task: build, attach source, pump at ~16ms.

use skyline::hooks::{getRegionAddress, Region};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mono_ms;

// `void submit(Task*)`. Same text offset on 13.0.4 and 13.0.5. The pump is what
// runs; a zero offset means the entry was not found and must not be called.
static mut REPLAY_SUBMIT_OFFSET: usize = 0x143d5d0;
// BSS box. `task = *(u64*)(*(u64*)(image + slot))`.
static mut REPLAY_TASK_SLOT_OFFSET: usize = 0x52c35b8;
// Results menu: alloc(align, size) then `ctor(box)` which stores the task in the box.
// The menu only runs this from its save step, which the direct path never enters.
static mut REPLAY_TASK_ALLOC_OFFSET: usize = 0x392e290;
static mut REPLAY_TASK_CTOR_OFFSET: usize = 0x143e850;
// `*(u64*)(image + slot)` is the replay manager. The menu calls
// `(*(manager+0x588))[0x18/8](manager+0x588)` and stores the result at task+0x198.
// The write callback bails when that field is still 0.
static mut REPLAY_SOURCE_OFFSET: usize = 0x52c50f0;
// Results pump. The menu calls this once a frame. State 1 enqueues, then
// later frames wait until the worker sets task+0x11c before advancing.
// Calling submit on the same tick replaces that callback, so the worker
// never opens a file.
static mut REPLAY_TASK_PUMP_OFFSET: usize = 0x143ea40;

/// Match ticks are once a millisecond. The results menu pumps once a frame,
/// and spinning the state machine faster than that hitches the results screen.
const REPLAY_PUMP_INTERVAL_MS: u64 = 16;

static PUMP_LIVE: AtomicBool = AtomicBool::new(false);
static PUMP_BUSY: AtomicBool = AtomicBool::new(false);
static PUMP_TASK: AtomicU64 = AtomicU64::new(0);
static PUMP_NOT_BEFORE: AtomicU64 = AtomicU64::new(0);
/// `mono_ms` when `task+0x108` first read 1 or 2. 0 while the task is still stepping.
static PUMP_SETTLED_AT: AtomicU64 = AtomicU64::new(0);

fn offset_to_addr(offset: usize) -> *const () {
    unsafe {
        (getRegionAddress(Region::Text) as *const u8).offset(offset as isize) as _
    }
}

/// True while the results task is still stepping, or for `grace_ms` after it
/// reports done. The vault file often closes in that window. Ending the wait
/// first gives the pads back, and the skip pulse never starts.
pub(crate) fn replay_pump_blocking_giveup(grace_ms: u64) -> bool {
    if !PUMP_LIVE.load(Ordering::SeqCst) {
        return false;
    }
    let settled = PUMP_SETTLED_AT.load(Ordering::SeqCst);
    if settled == 0 {
        return true;
    }
    mono_ms().saturating_sub(settled) < grace_ms
}

pub(crate) fn replay_submit_offset() -> usize {
    unsafe { REPLAY_SUBMIT_OFFSET }
}

pub(crate) unsafe fn apply_version_offsets(uses_13_0_5: bool) {
    if uses_13_0_5 {
        REPLAY_SUBMIT_OFFSET = 0x143d5d0;
        REPLAY_TASK_SLOT_OFFSET = 0x52c35b8;
        REPLAY_TASK_ALLOC_OFFSET = 0x392e290;
        REPLAY_TASK_CTOR_OFFSET = 0x143e850;
        REPLAY_SOURCE_OFFSET = 0x52c50f0;
        REPLAY_TASK_PUMP_OFFSET = 0x143ea40;
    } else {
        REPLAY_SUBMIT_OFFSET = 0x143d5d0;
        REPLAY_TASK_SLOT_OFFSET = 0x52c25b8;
        REPLAY_TASK_ALLOC_OFFSET = 0x392dce0;
        REPLAY_TASK_CTOR_OFFSET = 0x143e850;
        REPLAY_SOURCE_OFFSET = 0x52c40f0;
        REPLAY_TASK_PUMP_OFFSET = 0x143ea40;
    }
}

/// Allocate the 8-byte box and run the results-menu constructor.
/// Returns 0 when the allocator or the constructor offset is missing.
#[inline(never)]
unsafe fn make_replay_task_box() -> u64 {
    let alloc_off = REPLAY_TASK_ALLOC_OFFSET;
    let ctor_off = REPLAY_TASK_CTOR_OFFSET;
    if alloc_off == 0 || ctor_off == 0 {
        return 0;
    }
    let alloc: unsafe extern "C" fn(u64, u64) -> u64 =
        std::mem::transmute(offset_to_addr(alloc_off) as *const ());
    let ctor: unsafe extern "C" fn(u64) =
        std::mem::transmute(offset_to_addr(ctor_off) as *const ());
    // Same arguments the results menu passes: align 16, size 8.
    let box_ptr = std::hint::black_box(alloc)(0x10, 8);
    if box_ptr == 0 {
        return 0;
    }
    std::hint::black_box(ctor)(box_ptr);
    box_ptr
}

/// Same call the results menu makes after the constructor. Returns the pointer
/// stored at `task+0x198`, or 0 when the manager is not there.
#[inline(never)]
unsafe fn attach_replay_source(task: u64) -> u64 {
    let slot_off = REPLAY_SOURCE_OFFSET;
    if slot_off == 0 || task == 0 {
        return 0;
    }
    let root = *(offset_to_addr(slot_off) as *const u64);
    if root == 0 {
        return 0;
    }
    let vt = *((root + 0x588) as *const u64);
    if vt == 0 {
        return 0;
    }
    let method = *((vt + 0x18) as *const u64);
    if method == 0 {
        return 0;
    }
    let fetch: unsafe extern "C" fn(u64) -> u64 =
        std::mem::transmute(method as *const ());
    let replay = std::hint::black_box(fetch)(root + 0x588);
    *((task + 0x198) as *mut u64) = replay;
    replay
}

/// Drop the in-flight pump so the next dump wait builds a new task.
pub(crate) unsafe fn end_replay_pump() {
    PUMP_LIVE.store(false, Ordering::SeqCst);
    PUMP_TASK.store(0, Ordering::SeqCst);
    PUMP_NOT_BEFORE.store(0, Ordering::SeqCst);
    PUMP_SETTLED_AT.store(0, Ordering::SeqCst);
}

/// Build the task the way the results menu does, once per dump wait.
/// A fresh box each wait: a finished task left in the slot would not save again.
unsafe fn start_replay_task() -> bool {
    let slot_off = REPLAY_TASK_SLOT_OFFSET;
    let pump_off = REPLAY_TASK_PUMP_OFFSET;
    if slot_off == 0 || pump_off == 0 {
        return false;
    }
    let box_ptr = make_replay_task_box();
    if box_ptr == 0 {
        return false;
    }
    let slot = offset_to_addr(slot_off) as *mut u64;
    *slot = box_ptr;
    let task = *(box_ptr as *const u64);
    if task == 0 {
        return false;
    }
    attach_replay_source(task);
    *((task as *mut u8).add(0xa8) as *mut i32) = 1;
    *((task as *mut u8).add(0x108) as *mut u32) = 0;
    PUMP_TASK.store(task, Ordering::SeqCst);
    PUMP_SETTLED_AT.store(0, Ordering::SeqCst);
    true
}

/// One pump about every frame. The menu does this until `task+0x108` is 1 or 2.
/// Submit is a later state; calling it here overwrites the callback state 1 queued.
/// Also called from the pad hook: the results screen does not return through
/// `after_frame_tick`, so this is what advances the save there.
#[inline(never)]
pub(crate) unsafe fn pump_replay_save() {
    if PUMP_BUSY.swap(true, Ordering::SeqCst) {
        return;
    }
    let now = mono_ms();
    if PUMP_LIVE.load(Ordering::SeqCst) && now < PUMP_NOT_BEFORE.load(Ordering::SeqCst) {
        PUMP_BUSY.store(false, Ordering::SeqCst);
        return;
    }
    if !PUMP_LIVE.load(Ordering::SeqCst) {
        if !start_replay_task() {
            PUMP_BUSY.store(false, Ordering::SeqCst);
            return;
        }
        PUMP_LIVE.store(true, Ordering::SeqCst);
    }
    let task = PUMP_TASK.load(Ordering::SeqCst);
    let status_now = *((task as *const u8).add(0x108) as *const u32);
    if status_now == 1 || status_now == 2 {
        if PUMP_SETTLED_AT.load(Ordering::SeqCst) == 0 {
            PUMP_SETTLED_AT.store(now, Ordering::SeqCst);
        }
        PUMP_NOT_BEFORE.store(u64::MAX, Ordering::SeqCst);
        PUMP_BUSY.store(false, Ordering::SeqCst);
        return;
    }
    let pump_off = REPLAY_TASK_PUMP_OFFSET;
    let pump: unsafe extern "C" fn(u64) -> u32 =
        std::mem::transmute(offset_to_addr(pump_off) as *const ());
    std::hint::black_box(pump)(task);
    PUMP_NOT_BEFORE.store(now.saturating_add(REPLAY_PUMP_INTERVAL_MS), Ordering::SeqCst);
    PUMP_BUSY.store(false, Ordering::SeqCst);
}
