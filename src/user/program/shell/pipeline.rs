//! src/user/program/shell/pipeline.rs
//! Conditional chaining, pipeline splitting, redirect parsing — re-exported
//! from `ring3-common`.

pub(crate) use crate::user::shared::pipeline::{
    has_shell_operator, parse_redirects, split_pipeline, strip_trailing_newline,
    tokenize_conditionals, CondToken,
};
