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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityView<'a> {
    pub user: Option<Sid<'a>>,
    pub user_deny_only: bool,
    pub groups: &'a [SidAndAttributes<'a>],
}

impl<'a> TokenView<'a> {
    pub fn identity(&self) -> IdentityView<'a> {
        IdentityView {
            user: Some(self.user),
            user_deny_only: self.user_deny_only,
            groups: self.groups,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictedTokenContext<'a> {
    pub restricted_sids: &'a [SidAndAttributes<'a>],
    pub restricted_device_groups: &'a [SidAndAttributes<'a>],
    pub write_restricted: bool,
    pub privilege_granted: u32,
}

impl<'a> Default for RestrictedTokenContext<'a> {
    fn default() -> Self {
        Self {
            restricted_sids: &[],
            restricted_device_groups: &[],
            write_restricted: false,
            privilege_granted: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfinementTokenContext<'a> {
    pub confinement_sid: Option<Sid<'a>>,
    pub confinement_capabilities: &'a [SidAndAttributes<'a>],
    pub confinement_exempt: bool,
}

impl<'a> Default for ConfinementTokenContext<'a> {
    fn default() -> Self {
        Self {
            confinement_sid: None,
            confinement_capabilities: &[],
            confinement_exempt: false,
        }
    }
}
