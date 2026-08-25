//! src/user/program/shell/pipeline.rs
//!
//! Conditional chaining, pipeline splitting, redirect parsing — re-exported
//! from `ring3-common`.

pub(crate) use crate::user::shared::pipeline::has_shell_operator;
pub(crate) use crate::user::shared::pipeline::parse_redirects;
pub(crate) use crate::user::shared::pipeline::split_pipeline;
pub(crate) use crate::user::shared::pipeline::strip_trailing_newline;
pub(crate) use crate::user::shared::pipeline::tokenize_conditionals;
pub(crate) use crate::user::shared::pipeline::CondToken;
