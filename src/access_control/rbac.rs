use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Role-Based Access Control (RBAC) system
#[derive(Clone)]
pub struct RoleBasedAccessControl {
    config: RBACConfig,
    roles: Arc<RwLock<HashMap<String, Role>>>,
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
    user_roles: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    role_permissions: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACConfig {
    pub hierarchical_roles: bool,
    pub dynamic_permissions: bool,
    pub role_inheritance: bool,
    pub permission_caching: bool,
    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub level: u32,
    pub parent_roles: HashSet<String>,
    pub child_roles: HashSet<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub is_system_role: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub resource: String,
    pub action: String,
    pub description: String,
    pub scope: PermissionScope,
    pub conditions: Vec<PermissionCondition>,
    pub created_at: DateTime<Utc>,
    pub is_system_permission: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionScope {
    Global,
    Organization(String),
    Department(String),
    Team(String),
    Individual(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCondition {
    pub condition_type: ConditionType,
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    TimeRange,
    IpAddress,
    Location,
    DeviceType,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    GreaterThan,
    LessThan,
    In,
    NotIn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: String,
    pub user_id: String,
    pub role_id: String,
    pub assigned_by: String,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: PermissionScope,
    pub is_active: bool,
}

impl RoleBasedAccessControl {
    pub async fn new(config: RBACConfig) -> Result<Self, RBACError> {
        let rbac = Self {
            config,
            roles: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(HashMap::new())),
            user_roles: Arc::new(RwLock::new(HashMap::new())),
            role_permissions: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        };

        // Initialize system roles and permissions
        rbac.initialize_system_roles_and_permissions().await?;

        Ok(rbac)
    }

    pub async fn start(&self) -> Result<(), RBACError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(RBACError::AlreadyRunning);
        }
        *running = true;
        log::info!("RBAC system started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), RBACError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("RBAC system stopped");
        Ok(())
    }

    /// Create a new role
    pub async fn create_role(&self, role: Role) -> Result<(), RBACError> {
        let mut roles = self.roles.write().await;
        
        if roles.contains_key(&role.id) {
            return Err(RBACError::RoleAlreadyExists(role.id));
        }

        // Validate parent roles exist
        for parent_id in &role.parent_roles {
            if !roles.contains_key(parent_id) {
                return Err(RBACError::ParentRoleNotFound(parent_id.clone()));
            }
        }

        roles.insert(role.id.clone(), role);
        log::info!("Created role: {}", roles.len());
        Ok(())
    }

    /// Create a new permission
    pub async fn create_permission(&self, permission: Permission) -> Result<(), RBACError> {
        let mut permissions = self.permissions.write().await;
        
        if permissions.contains_key(&permission.id) {
            return Err(RBACError::PermissionAlreadyExists(permission.id));
        }

        permissions.insert(permission.id.clone(), permission);
        log::info!("Created permission: {}", permissions.len());
        Ok(())
    }

    /// Assign role to user
    pub async fn assign_role(&self, assignment: RoleAssignment) -> Result<(), RBACError> {
        // Verify role exists
        {
            let roles = self.roles.read().await;
            if !roles.contains_key(&assignment.role_id) {
                return Err(RBACError::RoleNotFound(assignment.role_id));
            }
        }

        let mut user_roles = self.user_roles.write().await;
        let user_role_set = user_roles.entry(assignment.user_id.clone()).or_insert_with(HashSet::new);
        user_role_set.insert(assignment.role_id.clone());

        log::info!("Assigned role {} to user {}", assignment.role_id, assignment.user_id);
        Ok(())
    }

    /// Assign permission to role
    pub async fn assign_permission_to_role(&self, role_id: &str, permission_id: &str) -> Result<(), RBACError> {
        // Verify role and permission exist
        {
            let roles = self.roles.read().await;
            if !roles.contains_key(role_id) {
                return Err(RBACError::RoleNotFound(role_id.to_string()));
            }
        }

        {
            let permissions = self.permissions.read().await;
            if !permissions.contains_key(permission_id) {
                return Err(RBACError::PermissionNotFound(permission_id.to_string()));
            }
        }

        let mut role_permissions = self.role_permissions.write().await;
        let role_permission_set = role_permissions.entry(role_id.to_string()).or_insert_with(HashSet::new);
        role_permission_set.insert(permission_id.to_string());

        log::info!("Assigned permission {} to role {}", permission_id, role_id);
        Ok(())
    }

    /// Check if user has specific permission
    pub async fn check_permission(&self, user_id: &str, resource: &str, action: &str) -> Result<bool, RBACError> {
        // Get user's roles
        let user_roles = {
            let user_roles_map = self.user_roles.read().await;
            user_roles_map.get(user_id).cloned().unwrap_or_default()
        };

        // Get all permissions for user's roles
        let mut user_permissions = HashSet::new();
        let role_permissions_map = self.role_permissions.read().await;
        
        for role_id in &user_roles {
            if let Some(role_perms) = role_permissions_map.get(role_id) {
                user_permissions.extend(role_perms.iter().cloned());
            }

            // Include inherited permissions if hierarchical roles are enabled
            if self.config.hierarchical_roles {
                let inherited_permissions = self.get_inherited_permissions(role_id).await?;
                user_permissions.extend(inherited_permissions);
            }
        }

        // Check if user has required permission
        let permissions_map = self.permissions.read().await;
        for permission_id in &user_permissions {
            if let Some(permission) = permissions_map.get(permission_id) {
                if self.permission_matches(permission, resource, action) {
                    // Check permission conditions
                    if self.evaluate_permission_conditions(permission, user_id).await? {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if user has admin role
    pub async fn user_has_admin_role(&self, user_id: &str) -> Result<bool, RBACError> {
        let user_roles_map = self.user_roles.read().await;
        if let Some(user_roles) = user_roles_map.get(user_id) {
            return Ok(user_roles.contains("admin") || user_roles.contains("super_admin"));
        }
        Ok(false)
    }

    /// Get user's effective permissions
    pub async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<Permission>, RBACError> {
        let user_roles = {
            let user_roles_map = self.user_roles.read().await;
            user_roles_map.get(user_id).cloned().unwrap_or_default()
        };

        let mut effective_permissions = HashSet::new();
        let role_permissions_map = self.role_permissions.read().await;
        
        for role_id in &user_roles {
            if let Some(role_perms) = role_permissions_map.get(role_id) {
                effective_permissions.extend(role_perms.iter().cloned());
            }

            if self.config.hierarchical_roles {
                let inherited_permissions = self.get_inherited_permissions(role_id).await?;
                effective_permissions.extend(inherited_permissions);
            }
        }

        let permissions_map = self.permissions.read().await;
        let result = effective_permissions
            .into_iter()
            .filter_map(|perm_id| permissions_map.get(&perm_id).cloned())
            .collect();

        Ok(result)
    }

    /// Get user's roles
    pub async fn get_user_roles(&self, user_id: &str) -> Result<Vec<Role>, RBACError> {
        let user_roles = {
            let user_roles_map = self.user_roles.read().await;
            user_roles_map.get(user_id).cloned().unwrap_or_default()
        };

        let roles_map = self.roles.read().await;
        let result = user_roles
            .into_iter()
            .filter_map(|role_id| roles_map.get(&role_id).cloned())
            .collect();

        Ok(result)
    }

    /// Remove role from user
    pub async fn revoke_role(&self, user_id: &str, role_id: &str) -> Result<(), RBACError> {
        let mut user_roles = self.user_roles.write().await;
        if let Some(user_role_set) = user_roles.get_mut(user_id) {
            user_role_set.remove(role_id);
            log::info!("Revoked role {} from user {}", role_id, user_id);
        }
        Ok(())
    }

    /// Remove permission from role
    pub async fn revoke_permission_from_role(&self, role_id: &str, permission_id: &str) -> Result<(), RBACError> {
        let mut role_permissions = self.role_permissions.write().await;
        if let Some(role_permission_set) = role_permissions.get_mut(role_id) {
            role_permission_set.remove(permission_id);
            log::info!("Revoked permission {} from role {}", permission_id, role_id);
        }
        Ok(())
    }

    // Private helper methods

    async fn initialize_system_roles_and_permissions(&self) -> Result<(), RBACError> {
        // Create system permissions
        let system_permissions = vec![
            Permission {
                id: "read_files".to_string(),
                name: "Read Files".to_string(),
                resource: "file".to_string(),
                action: "read".to_string(),
                description: "Permission to read files".to_string(),
                scope: PermissionScope::Global,
                conditions: Vec::new(),
                created_at: Utc::now(),
                is_system_permission: true,
            },
            Permission {
                id: "write_files".to_string(),
                name: "Write Files".to_string(),
                resource: "file".to_string(),
                action: "write".to_string(),
                description: "Permission to write files".to_string(),
                scope: PermissionScope::Global,
                conditions: Vec::new(),
                created_at: Utc::now(),
                is_system_permission: true,
            },
            Permission {
                id: "delete_files".to_string(),
                name: "Delete Files".to_string(),
                resource: "file".to_string(),
                action: "delete".to_string(),
                description: "Permission to delete files".to_string(),
                scope: PermissionScope::Global,
                conditions: Vec::new(),
                created_at: Utc::now(),
                is_system_permission: true,
            },
            Permission {
                id: "manage_users".to_string(),
                name: "Manage Users".to_string(),
                resource: "user".to_string(),
                action: "*".to_string(),
                description: "Permission to manage users".to_string(),
                scope: PermissionScope::Global,
                conditions: Vec::new(),
                created_at: Utc::now(),
                is_system_permission: true,
            },
            Permission {
                id: "admin_access".to_string(),
                name: "Admin Access".to_string(),
                resource: "*".to_string(),
                action: "*".to_string(),
                description: "Full administrative access".to_string(),
                scope: PermissionScope::Global,
                conditions: Vec::new(),
                created_at: Utc::now(),
                is_system_permission: true,
            },
        ];

        // Create system roles
        let system_roles = vec![
            Role {
                id: "user".to_string(),
                name: "User".to_string(),
                description: "Basic user role".to_string(),
                level: 1,
                parent_roles: HashSet::new(),
                child_roles: HashSet::new(),
                created_at: Utc::now(),
                created_by: "system".to_string(),
                is_system_role: true,
                metadata: HashMap::new(),
            },
            Role {
                id: "admin".to_string(),
                name: "Administrator".to_string(),
                description: "Administrative role".to_string(),
                level: 2,
                parent_roles: ["user".to_string()].into_iter().collect(),
                child_roles: HashSet::new(),
                created_at: Utc::now(),
                created_by: "system".to_string(),
                is_system_role: true,
                metadata: HashMap::new(),
            },
            Role {
                id: "super_admin".to_string(),
                name: "Super Administrator".to_string(),
                description: "Super administrative role".to_string(),
                level: 3,
                parent_roles: ["admin".to_string()].into_iter().collect(),
                child_roles: HashSet::new(),
                created_at: Utc::now(),
                created_by: "system".to_string(),
                is_system_role: true,
                metadata: HashMap::new(),
            },
        ];

        // Insert permissions
        let mut permissions = self.permissions.write().await;
        for permission in system_permissions {
            permissions.insert(permission.id.clone(), permission);
        }
        drop(permissions);

        // Insert roles
        let mut roles = self.roles.write().await;
        for role in system_roles {
            roles.insert(role.id.clone(), role);
        }
        drop(roles);

        // Assign permissions to roles
        let mut role_permissions = self.role_permissions.write().await;
        
        // User role gets basic permissions
        let user_permissions: HashSet<String> = ["read_files"].iter().map(|s| s.to_string()).collect();
        role_permissions.insert("user".to_string(), user_permissions);
        
        // Admin role gets user management permissions
        let admin_permissions: HashSet<String> = ["read_files", "write_files", "delete_files", "manage_users"]
            .iter().map(|s| s.to_string()).collect();
        role_permissions.insert("admin".to_string(), admin_permissions);
        
        // Super admin gets all permissions
        let super_admin_permissions: HashSet<String> = ["read_files", "write_files", "delete_files", "manage_users", "admin_access"]
            .iter().map(|s| s.to_string()).collect();
        role_permissions.insert("super_admin".to_string(), super_admin_permissions);

        log::info!("Initialized system roles and permissions");
        Ok(())
    }

    async fn get_inherited_permissions(&self, role_id: &str) -> Result<HashSet<String>, RBACError> {
        let mut inherited_permissions = HashSet::new();
        
        let roles_map = self.roles.read().await;
        let role_permissions_map = self.role_permissions.read().await;
        
        if let Some(role) = roles_map.get(role_id) {
            // Get permissions from parent roles recursively
            for parent_id in &role.parent_roles {
                if let Some(parent_permissions) = role_permissions_map.get(parent_id) {
                    inherited_permissions.extend(parent_permissions.iter().cloned());
                }
                
                // Recursively get permissions from parent's parents
                let parent_inherited = self.get_inherited_permissions_internal(parent_id, &roles_map, &role_permissions_map)?;
                inherited_permissions.extend(parent_inherited);
            }
        }

        Ok(inherited_permissions)
    }

    fn get_inherited_permissions_internal(
        &self,
        role_id: &str,
        roles_map: &HashMap<String, Role>,
        role_permissions_map: &HashMap<String, HashSet<String>>,
    ) -> Result<HashSet<String>, RBACError> {
        let mut inherited_permissions = HashSet::new();
        
        if let Some(role) = roles_map.get(role_id) {
            for parent_id in &role.parent_roles {
                if let Some(parent_permissions) = role_permissions_map.get(parent_id) {
                    inherited_permissions.extend(parent_permissions.iter().cloned());
                }
                
                let parent_inherited = self.get_inherited_permissions_internal(parent_id, roles_map, role_permissions_map)?;
                inherited_permissions.extend(parent_inherited);
            }
        }

        Ok(inherited_permissions)
    }

    fn permission_matches(&self, permission: &Permission, resource: &str, action: &str) -> bool {
        let resource_matches = permission.resource == "*" || permission.resource == resource;
        let action_matches = permission.action == "*" || permission.action == action;
        
        resource_matches && action_matches
    }

    async fn evaluate_permission_conditions(&self, permission: &Permission, _user_id: &str) -> Result<bool, RBACError> {
        // For now, just return true if no conditions
        if permission.conditions.is_empty() {
            return Ok(true);
        }

        // In a real implementation, would evaluate conditions like:
        // - Time ranges
        // - IP address restrictions  
        // - Location-based access
        // - Device type restrictions
        
        Ok(true)
    }
}

impl Default for RBACConfig {
    fn default() -> Self {
        Self {
            hierarchical_roles: true,
            dynamic_permissions: false,
            role_inheritance: true,
            permission_caching: true,
            cache_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RBACError {
    #[error("RBAC system already running")]
    AlreadyRunning,
    
    #[error("RBAC system not running")]
    NotRunning,
    
    #[error("Role already exists: {0}")]
    RoleAlreadyExists(String),
    
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    
    #[error("Parent role not found: {0}")]
    ParentRoleNotFound(String),
    
    #[error("Permission already exists: {0}")]
    PermissionAlreadyExists(String),
    
    #[error("Permission not found: {0}")]
    PermissionNotFound(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Circular role dependency detected")]
    CircularDependency,
    
    #[error("Invalid role hierarchy")]
    InvalidHierarchy,
}