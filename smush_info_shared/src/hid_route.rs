//! Controller style of one `GetNpadState` poll.
//!
//! The results skip pulse uses this so a sideways Joy-Con still receives A.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PadKind {
    FullKey,
    Handheld,
    JoyDual,
    Gc,
    JoyLeft,
    JoyRight,
}
