//! A small program for the exporter's end-to-end test: named functions, a
//! struct, an enum and a global that the test expects to find in the IR.
//!
//! The functions use the C ABI and unmangled names so their names and
//! signatures in the program database are predictable.

use std::hint::black_box;

/// A 3D vector.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Vector3 {
    /// X.
    pub x: f32,
    /// Y.
    pub y: f32,
    /// Z.
    pub z: f32,
}

/// What an entity is.
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum EntityKind {
    /// Nothing.
    None = 0,
    /// The player.
    Player = 1,
    /// Another character.
    Npc = 2,
}

/// An entity in the world.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Entity {
    /// What it is.
    pub kind: EntityKind,
    /// Where it is.
    pub position: Vector3,
    /// Its health.
    pub health: f32,
}

/// Gravity, a global the test expects in the IR.
#[unsafe(no_mangle)]
pub static mut fixture_gravity: f32 = 9.81;

/// Adds two numbers.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_add(a: i32, b: i32) -> i32 {
    black_box(a).wrapping_add(black_box(b))
}

/// Moves a byte by a signed offset, saturating.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_nudge(value: u8, offset: i8) -> u8 {
    black_box(value).saturating_add_signed(black_box(offset))
}

/// Returns the length of a vector.
///
/// # Safety
///
/// `v` must point to a valid `Vector3`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixture_length(v: *const Vector3) -> f32 {
    // SAFETY: The caller passes a valid vector.
    let v = unsafe { &*v };
    (v.x * v.x + v.y * v.y + v.z * v.z).sqrt()
}

/// Damages an entity.
///
/// # Safety
///
/// `entity` must point to a valid, exclusive `Entity`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixture_damage(entity: *mut Entity, amount: f32) {
    // SAFETY: The caller passes a valid, exclusive entity.
    unsafe { (*entity).health -= black_box(amount) };
}

fn main() {
    let mut entity = Entity {
        kind: EntityKind::Player,
        position: Vector3 {
            x: 1.0,
            y: 2.0,
            z: 2.0,
        },
        health: 100.0,
    };
    // SAFETY: `entity` is a valid, exclusive local.
    unsafe { fixture_damage(black_box(&mut entity), 10.0) };
    // SAFETY: `entity.position` is a valid vector.
    let length = unsafe { fixture_length(&entity.position) };
    // SAFETY: Single-threaded access to the global.
    let gravity = unsafe { black_box(fixture_gravity) };
    println!(
        "{} {} {length} {gravity} {:?}",
        fixture_add(2, 3),
        fixture_nudge(200, -8),
        black_box(entity)
    );
}
