use serde::{Deserialize, Serialize};

/// User information extracted from authentik proxy headers after successful authentication.
///
/// The authentik Proxy Provider forwards user identity via HTTP headers
/// (e.g., `x-authentik-username`, `x-authentik-email`, `x-authentik-groups`).
/// This struct represents the deserialized user information available to downstream services.
///
/// # Future compatibility
///
/// This struct is `#[non_exhaustive]` so that new fields can be added in the future
/// without breaking existing code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthentikUser {
    /// The username (sub claim in OIDC terms).
    pub username: String,
    /// The email address.
    pub email: String,
    /// The display name / full name.
    pub name: String,
    /// The user ID (sub / uid).
    pub uid: String,
    /// The list of groups the user belongs to.
    pub groups: Vec<String>,
}

impl AuthentikUser {
    /// Returns `true` if the user belongs to the specified group.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if user.has_group("admin") {
    ///     // allow access
    /// }
    /// ```
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// Returns `true` if the user belongs to **all** of the specified groups.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if user.has_all_groups(&["admin", "editor"]) {
    ///     // allow access
    /// }
    /// ```
    pub fn has_all_groups(&self, groups: &[&str]) -> bool {
        groups.iter().all(|g| self.has_group(g))
    }

    /// Returns `true` if the user belongs to **any** of the specified groups.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if user.has_any_group(&["admin", "moderator"]) {
    ///     // allow access
    /// }
    /// ```
    pub fn has_any_group(&self, groups: &[&str]) -> bool {
        groups.iter().any(|g| self.has_group(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(groups: &[&str]) -> AuthentikUser {
        AuthentikUser {
            username: "testuser".into(),
            email: "test@example.com".into(),
            name: "Test User".into(),
            uid: "user-001".into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    #[test]
    fn test_has_group() {
        let user = make_user(&["admin", "editor"]);
        assert!(user.has_group("admin"));
        assert!(user.has_group("editor"));
        assert!(!user.has_group("viewer"));
    }

    #[test]
    fn test_has_group_empty() {
        let user = make_user(&[]);
        assert!(!user.has_group("admin"));
    }

    #[test]
    fn test_has_all_groups() {
        let user = make_user(&["admin", "editor", "viewer"]);
        assert!(user.has_all_groups(&["admin", "editor"]));
        assert!(user.has_all_groups(&["admin"]));
        assert!(!user.has_all_groups(&["admin", "superuser"]));
    }

    #[test]
    fn test_has_all_groups_empty_input() {
        let user = make_user(&["admin"]);
        // all() on empty iterator returns true
        assert!(user.has_all_groups(&[]));
    }

    #[test]
    fn test_has_any_group() {
        let user = make_user(&["admin", "editor"]);
        assert!(user.has_any_group(&["admin", "viewer"]));
        assert!(user.has_any_group(&["editor"]));
        assert!(!user.has_any_group(&["viewer", "superuser"]));
    }

    #[test]
    fn test_has_any_group_empty_input() {
        let user = make_user(&["admin"]);
        // any() on empty iterator returns false
        assert!(!user.has_any_group(&[]));
    }

    #[test]
    fn test_serde_roundtrip() {
        let user = make_user(&["admin", "users"]);
        let json = serde_json::to_string(&user).unwrap();
        let parsed: AuthentikUser = serde_json::from_str(&json).unwrap();
        assert_eq!(user.username, parsed.username);
        assert_eq!(user.groups, parsed.groups);
    }
}
