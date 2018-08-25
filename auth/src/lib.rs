#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure_derive;

pub mod model;

use std::collections::HashMap;

#[derive(Fail, Debug)]
pub enum AuthError {
    #[fail(display = "UnAuthenticatedError")]
    UnAuthenticatedError {},
    #[fail(display = "NoRequiredRole [{}]", role)]
    NoRequiredRole { role: String },
    #[fail(display = "NoRequiredResource [{}]", resource)]
    NoRequiredResource { resource: String },
    #[fail(display = "NoRequiredPermission [{}]", permission)]
    NoRequiredPermission { permission: String },
}

pub struct AuthService {
    roles_provider: Box<dyn RolesProvider>
}

pub fn new(roles_provider: Box<dyn RolesProvider>) -> AuthService {
    AuthService {
        roles_provider
    }
}

impl AuthService {
    pub fn auth(&self, auth: model::Auth) -> AuthContext<'_> {
        AuthContext::new(auth, &self.roles_provider)
    }
}

pub struct AuthContext<'a> {
    pub auth: model::Auth,
    permissions: HashMap<&'a model::Resource, &'a Vec<String>>
}

impl<'a> AuthContext<'a> {

    pub fn new(auth: model::Auth, roles_provider: & Box<dyn RolesProvider>) -> AuthContext<'_> {

        let mut permissions = HashMap::new();

        for role in roles_provider.get_by_name(&auth.roles) {
            for (resource, permission) in role.permissions.iter() {
                permissions.insert(resource, permission);
            }
        }

        AuthContext {
            auth,
            permissions
        }
    }

    pub fn is_authenticated(&self) -> Result<&AuthContext<'_>, AuthError> {
        if self.auth.username.is_empty() {
            return Err(AuthError::UnAuthenticatedError {});
        };
        Ok(&self)
    }

    pub fn has_role(&self, role: &str) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        if !self.has_role_bool(&role) {
            return Err(AuthError::NoRequiredRole { role: role.to_string() });
        };
        Ok(&self)
    }

    pub fn has_any_role(&self, roles: &[&str]) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        for role in roles {
            if self.has_role_bool(*role) {
                return Ok(&self);
            };
        };
        return Err(AuthError::NoRequiredRole { role: "".to_string() });
    }

    pub fn has_all_roles(&self, roles: &[&str]) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        for role in roles {
            if !self.has_role_bool(*role) {
                return Err(AuthError::NoRequiredRole { role: role.to_string() });
            };
        };
        return Ok(&self);
    }

    pub fn has_resource(&self, resource: &str) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        if !self.has_resource_bool(&resource) {
            return Err(AuthError::NoRequiredResource { resource: resource.to_string() });
        };
        Ok(&self)
    }

    pub fn has_any_resource(&self, resources: &[&str]) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        for resource in resources {
            if self.has_resource_bool(*resource) {
                return Ok(&self);
            };
        };
        return Err(AuthError::NoRequiredResource { resource: "".to_string() });
    }

    pub fn has_all_resources(&self, resources: &[&str]) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        for resource in resources {
            if !self.has_resource_bool(*resource) {
                return Err(AuthError::NoRequiredResource { resource: resource.to_string() });
            };
        };
        return Ok(&self);
    }

    pub fn has_permission(&self, resource: &model::Resource, permission: &str) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        if !self.has_permission_bool(resource, permission) {
            return Err(AuthError::NoRequiredPermission { permission: permission.to_string() });
        };
        Ok(&self)
    }

    pub fn has_any_permission(&self, resource: &model::Resource, permissions: &[&str]) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        for permission in permissions {
            if self.has_permission_bool(resource, *permission) {
                return Ok(&self);
            };
        };
        return Err(AuthError::NoRequiredPermission { permission: "".to_string() });
    }

    pub fn has_all_permissions(&self, resource: &model::Resource, permissions: &[&str]) -> Result<&AuthContext<'_>, AuthError> {
        self.is_authenticated()?;
        for permission in permissions {
            if !self.has_permission_bool(resource, *permission) {
                return Err(AuthError::NoRequiredPermission { permission: permission.to_string() });
            };
        };
        return Ok(&self);
    }

    fn has_role_bool(&self, role: &str) -> bool {
        self.auth.roles.contains(&role.to_string())
    }

    fn has_resource_bool(&self, resource: &str) -> bool {
        self.auth.resources.contains(&resource.to_string())
    }

    fn has_permission_bool(&self, resource: &model::Resource, permission: &str) -> bool {
        if let Some(p_over_res) = self.permissions.get(&resource) {
            p_over_res.contains(&permission.to_string())
        } else {
            false
        }
    }
}

pub trait RolesProvider: Send + Sync {
    fn get_all(&self) -> &Vec<model::Role>;

    fn get_by_name(&self, names: &Vec<String>) -> Vec<&model::Role>;
}

pub trait ResourcesProvider: Send + Sync {
    fn get_all(&self) -> &Vec<model::Resource>;

    fn get_by_name(&self, names: &Vec<String>) -> Vec<&model::Resource>;
}

pub struct InMemoryRolesProvider {
    all_roles: Vec<model::Role>,
    roles_by_name: HashMap<String, model::Role>,
}

pub struct InMemoryResourcesProvider {
    all_resources: Vec<model::Resource>,
    resources_by_name: HashMap<String, model::Resource>,
}

impl InMemoryResourcesProvider {
    pub fn new(all_resources: Vec<model::Resource>) -> InMemoryResourcesProvider {
        let mut provider = InMemoryResourcesProvider {
            all_resources,
            resources_by_name: HashMap::new(),
        };

        for resource in &provider.all_resources {
            provider.resources_by_name.insert(resource.name.clone(), resource.clone());
        }

        provider
    }
}

impl RolesProvider for InMemoryRolesProvider {
    fn get_all(&self) -> &Vec<model::Role> {
        &self.all_roles
    }

    fn get_by_name(&self, names: &Vec<String>) -> Vec<&model::Role> {
        let mut result = vec![];
        for name in names {
            match self.roles_by_name.get(name) {
                Some(t) => result.push(t),
                None => {}
            }
        };
        result
    }
}

impl ResourcesProvider for InMemoryResourcesProvider {
    fn get_all(&self) -> &Vec<model::Resource> {
        &self.all_resources
    }

    fn get_by_name(&self, names: &Vec<String>) -> Vec<&model::Resource> {
        let mut result = vec![];
        for name in names {
            match self.resources_by_name.get(name) {
                Some(t) => result.push(t),
                None => {}
            }
        };
        result
    }
}

#[cfg(test)]
mod test_role_provider {
    use super::model::Role;
    use super::RolesProvider;

    #[test]
    fn should_return_all_roles() {
        let roles = vec![
            Role {
                id: 0,
                name: "RoleOne".to_string(),
                permissions: vec![],
            },
            Role {
                id: 1,
                name: "RoleTwo".to_string(),
                permissions: vec![],
            }
        ];
        let provider = super::InMemoryRolesProvider::new(roles.clone());
        let get_all = provider.get_all();
        assert!(!get_all.is_empty());
        assert_eq!(roles.len(), get_all.len());
        assert_eq!(&roles[0].name, &get_all[0].name);
        assert_eq!(&roles[1].name, &get_all[1].name);
    }

    #[test]
    fn should_return_empty_if_no_matching_names() {
        let roles = vec![
            Role {
                id: 0,
                name: "RoleOne".to_string(),
                permissions: vec![],
            },
            Role {
                id: 1,
                name: "RoleTwo".to_string(),
                permissions: vec![],
            }
        ];
        let provider = super::InMemoryRolesProvider::new(roles.clone());
        let get_by_name = provider.get_by_name(&vec![]);
        assert!(get_by_name.is_empty());
    }

    #[test]
    fn should_return_role_by_name() {
        let roles = vec![
            Role {
                id: 0,
                name: "RoleOne".to_string(),
                permissions: vec![],
            },
            Role {
                id: 1,
                name: "RoleTwo".to_string(),
                permissions: vec![],
            }
        ];
        let provider = super::InMemoryRolesProvider::new(roles.clone());
        let get_by_name = provider.get_by_name(&vec!["RoleOne".to_string()]);
        assert!(!get_by_name.is_empty());
        assert_eq!(1, get_by_name.len());
        assert_eq!("RoleOne", &get_by_name[0].name);
    }
}


#[cfg(test)]
mod test_auth_context {

    use super::model::{Auth, Role};

    #[test]
    fn should_be_authenticated() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec![],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.is_authenticated().is_ok());
    }

    #[test]
    fn should_be_not_authenticated() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "".to_string(),
            roles: vec![],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.is_authenticated().is_err());
    }

    #[test]
    fn should_be_not_authenticated_even_if_has_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_role("ADMIN").is_err());
    }

    #[test]
    fn should_have_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_role("ADMIN").is_ok());
    }

    #[test]
    fn should_have_role_2() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_role("USER").is_ok());
    }

    #[test]
    fn should_not_have_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_role("USER").is_err());
    }

    #[test]
    fn should_have_any_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_any_role(&["USER", "FRIEND"]).is_ok());
    }

    #[test]
    fn should_not_have_any_role() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "OWNER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_any_role(&["USER", "FRIEND"]).is_err());
    }

    #[test]
    fn should_have_all_roles() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string(), "FRIEND".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_all_roles(&["USER", "FRIEND"]).is_ok());
    }

    #[test]
    fn should_not_have_all_roles() {
        let provider = Box::new(super::InMemoryRolesProvider::new(vec![]));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "USER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_all_roles(&["USER", "FRIEND"]).is_err());
    }

    #[test]
    fn should_be_not_authenticated_even_if_has_permission() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_permission("delete").is_err());
    }

    #[test]
    fn should_have_permission() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["create".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_permission("delete").is_ok());
    }

    #[test]
    fn should_have_permission_2() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["ADMIN".to_string(), "OWNER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_permission("delete").is_ok());
    }

    #[test]
    fn should_not_have_permission() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_permission("delete").is_err());
    }

    #[test]
    fn should_have_any_permission() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["superDelete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_any_permission(&["delete", "superDelete"]).is_ok());
    }

    #[test]
    fn should_not_have_any_permission() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["delete".to_string(), "superDelete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_any_permission(&["delete", "superAdmin"]).is_err());
    }

    #[test]
    fn should_have_all_permissions() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["superDelete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            },
            Role {
                id: 2,
                name: "USER".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_all_permissions(&["delete", "superDelete"]).is_ok());
    }

    #[test]
    fn should_not_have_all_permissions() {
        let roles = vec![
            Role {
                id: 0,
                name: "ADMIN".to_string(),
                permissions: vec!["superDelete".to_string()],
            },
            Role {
                id: 1,
                name: "OWNER".to_string(),
                permissions: vec!["delete".to_string()],
            }
        ];
        let provider = Box::new(super::InMemoryRolesProvider::new(roles.clone()));
        let auth_service = super::AuthService{ roles_provider: provider};
        let user = Auth {
            id: 0,
            username: "name".to_string(),
            roles: vec!["USER".to_string(), "ADMIN".to_string()],
        };
        let auth_context = auth_service.auth( user );
        assert!(auth_context.has_all_permissions(&["delete", "superDelete"]).is_err());
    }

}
