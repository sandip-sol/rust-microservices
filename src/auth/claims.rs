use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub exp: usize,
    pub iat: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Admin,
    Service,
}

impl Role {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            "service" => Some(Self::Service),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Service => "service",
        }
    }

    pub fn can_access(self, required: Role) -> bool {
        self == required || matches!((self, required), (Self::Admin, Self::User))
    }
}

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn role_parser_accepts_supported_roles() {
        assert_eq!(Role::parse("user"), Some(Role::User));
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("service"), Some(Role::Service));
        assert_eq!(Role::parse("owner"), None);
    }

    #[test]
    fn admin_can_access_user_routes_but_service_cannot() {
        assert!(Role::Admin.can_access(Role::User));
        assert!(Role::User.can_access(Role::User));
        assert!(!Role::Service.can_access(Role::User));
        assert!(!Role::User.can_access(Role::Admin));
    }
}
