// In milu/src/parser/test_utils.rs

// These macros rely on types being in scope at the call site.
// For `Value`, `Arc`, etc., this means `use crate::script::Value; use std::sync::Arc;`
// For `Not`, `Plus`, etc., this means `use crate::script::stdlib::Not;`
// The macros themselves use fully qualified paths like `crate::script::Value` to be robust.

// The expr! macro is no longer needed if we define each helper macro directly.
// If it were kept, its definition would go here.
// For now, we define each macro like plus!, not!, etc., individually.

#[macro_export]
macro_rules! id {
    ($st:expr) => {
        $crate::script::Value::Identifier($st.to_string())
    };
}
#[macro_export]
macro_rules! str {
    ($st:expr) => {
        $crate::script::Value::String($st.to_string())
    };
}
#[macro_export]
macro_rules! int {
    ($st:expr) => {
        $crate::script::Value::Integer($st)
    };
}
#[macro_export]
macro_rules! bool {
    ($st:expr) => {
        $crate::script::Value::Boolean($st)
    };
}
#[macro_export]
macro_rules! array { ($($st:expr),*) => { $crate::script::Value::Array(std::sync::Arc::new(vec![$($st),*])) }; }
#[macro_export]
macro_rules! tuple { ($($st:expr),*) => { $crate::script::Value::Tuple(std::sync::Arc::new(vec![$($st),*])) }; }

// Manually defined macros previously generated by expr!
#[macro_export]
macro_rules! not {
    ($p1:expr) => {
        $crate::script::stdlib::Not::make_call($p1).into()
    };
}
#[macro_export]
macro_rules! bit_not {
    ($p1:expr) => {
        $crate::script::stdlib::BitNot::make_call($p1).into()
    };
}
#[macro_export]
macro_rules! neg {
    ($p1:expr) => {
        $crate::script::stdlib::Negative::make_call($p1).into()
    };
}

#[macro_export]
macro_rules! and {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::And::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! or {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Or::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! band {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::BitAnd::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! bor {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::BitOr::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! bxor {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::BitXor::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! plus {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Plus::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! minus {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Minus::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! mul {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Multiply::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! div {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Divide::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! equal {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Equal::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! member_of {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::IsMemberOf::make_call($p1, $p2).into()
    };
}

#[macro_export]
macro_rules! call {
    ($p1:expr) => { $crate::script::Call::new($p1).into() }; // Corrected path
    ($($p:expr),+ $(,)?) => { $crate::script::Call::new(vec![$($p),*]).into() }; // Corrected path
}
#[macro_export]
macro_rules! scope {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Scope::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! index {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Index::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! access {
    ($p1:expr,$p2:expr) => {
        $crate::script::stdlib::Access::make_call($p1, $p2).into()
    };
}
#[macro_export]
macro_rules! branch {
    ($p1:expr,$p2:expr,$p3:expr) => {
        $crate::script::stdlib::If::make_call($p1, $p2, $p3).into()
    };
}
#[macro_export]
macro_rules! strcat {
    ($p1:expr) => {
        $crate::script::stdlib::StringConcat::make_call($p1).into()
    };
}
