//! Unions in the engine (M4).
use eigen_core::cell::{Item, Mbox};
use eigen_core::identity::Who;

use crate::app::App;
use crate::engine::Engine;

pub struct UnionState {
    pub msg_ttl: u32,
}

pub fn tick(_: &mut Engine, _: &mut App) {}
pub fn on_blob(_: &mut Engine, _: u64, _: &Mbox, _: &Item, _: &mut App) {}
pub fn say(_: &mut Engine, _: u64, _: String, app: &mut App) {
    app.here_notice("unions are not built yet.");
}
pub fn leave(_: &mut Engine, _: u64, _: &mut App) {}
pub fn create(_: &mut Engine, _: Option<String>, app: &mut App) {
    app.here_notice("unions are not built yet.");
}
pub fn join(_: &mut Engine, _: &str, app: &mut App) {
    app.here_notice("unions are not built yet.");
}
pub fn renew(_: &mut Engine, _: u64, _: &mut App) {}
pub fn drop_vote(_: &mut Engine, _: u64, _: &str, _: &mut App) {}
pub fn member_named(_: &Engine, _: u64, _: &str) -> Option<Who> {
    None
}
