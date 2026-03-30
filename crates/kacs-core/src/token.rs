use crate::sid::Sid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SidAndAttributes<'a> {
    pub sid: Sid<'a>,
    pub attributes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenView<'a> {
    pub user: Sid<'a>,
    pub user_deny_only: bool,
    pub groups: &'a [SidAndAttributes<'a>],
}
