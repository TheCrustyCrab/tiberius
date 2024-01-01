use std::fmt::Debug;

#[derive(Clone, PartialEq, Eq)]
pub struct SqlServerAuth {
    user: String,
    password: String,
}

impl SqlServerAuth {
    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl Debug for SqlServerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlServerAuth")
            .field("user", &self.user)
            .field("password", &"<HIDDEN>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg(any(all(windows, feature = "winauth"), doc))]
#[cfg_attr(feature = "docs", doc(all(windows, feature = "winauth")))]
pub struct WindowsAuth {
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) domain: Option<String>,
}

#[cfg(any(all(windows, feature = "winauth"), doc))]
#[cfg_attr(feature = "docs", doc(all(windows, feature = "winauth")))]
impl Debug for WindowsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsAuth")
            .field("user", &self.user)
            .field("password", &"<HIDDEN>")
            .field("domain", &self.domain)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg(feature="aad")]
pub struct AADManagedIdentityAuth {
    client_id: Option<String>
}

#[cfg(feature="aad")]
impl AADManagedIdentityAuth {
    pub(crate) fn client_id(&self) -> Option<&str> {
        self.client_id.as_ref().map(String::as_ref)
    }
}

#[cfg(feature="aad")]
impl Debug for AADManagedIdentityAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AADManagedIdentityAuth")
            .field("client_id", &self.client_id)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg(feature="aad")]
pub struct AADServicePrincipalAuth {
    client_id: String,
    client_secret: String
}

#[cfg(feature="aad")]
impl AADServicePrincipalAuth {
    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn client_secret(&self) -> &str {
        &self.client_secret
    }
}

#[cfg(feature="aad")]
impl Debug for AADServicePrincipalAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AADServicePrincipalAuth")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .finish()
    }
}

/// Defines the method of authentication to the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Authenticate directly with SQL Server.
    SqlServer(SqlServerAuth),
    /// Authenticate with Windows credentials.
    #[cfg(any(all(windows, feature = "winauth"), doc))]
    #[cfg_attr(feature = "docs", doc(cfg(all(windows, feature = "winauth"))))]
    Windows(WindowsAuth),
    /// Authenticate as the currently logged in user. On Windows uses SSPI and
    /// Kerberos on Unix platforms.
    #[cfg(any(
        all(windows, feature = "winauth"),
        all(unix, feature = "integrated-auth-gssapi"),
        doc
    ))]
    #[cfg_attr(
        feature = "docs",
        doc(cfg(any(windows, all(unix, feature = "integrated-auth-gssapi"))))
    )]
    Integrated,
    /// Authenticate with an AAD token. The token should encode an AAD user/service principal
    /// which has access to SQL Server.
    AADToken(String),
    /// Authenticate as a system-assigned or user-assigned managed identity with an optional client id.
    #[cfg(feature="aad")]
    AADManagedIdentity(AADManagedIdentityAuth),
    /// Authenticate as a service principal with a client id and secret.
    #[cfg(feature="aad")]
    AADServicePrincipal(AADServicePrincipalAuth),
    #[doc(hidden)]
    None,
}

impl AuthMethod {
    /// Construct a new SQL Server authentication configuration.
    pub fn sql_server(user: impl ToString, password: impl ToString) -> Self {
        Self::SqlServer(SqlServerAuth {
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    /// Construct a new Windows authentication configuration.
    #[cfg(any(all(windows, feature = "winauth"), doc))]
    #[cfg_attr(feature = "docs", doc(cfg(all(windows, feature = "winauth"))))]
    pub fn windows(user: impl AsRef<str>, password: impl ToString) -> Self {
        let (domain, user) = match user.as_ref().find('\\') {
            Some(idx) => (Some(&user.as_ref()[..idx]), &user.as_ref()[idx + 1..]),
            _ => (None, user.as_ref()),
        };

        Self::Windows(WindowsAuth {
            user: user.to_string(),
            password: password.to_string(),
            domain: domain.map(|s| s.to_string()),
        })
    }

    /// Construct a new configuration with AAD auth token.
    pub fn aad_token(token: impl ToString) -> Self {
        Self::AADToken(token.to_string())
    }

    /// Constructs a new AAD configuration to authenticate with a system-assigned managed identity 
    /// or the single user-assigned managed identity.
    /// In case there are multiple user-assigned managed identities, use `aad_managed_identity_with_client_id`.
    #[cfg(feature="aad")]
    pub fn aad_managed_identity() -> Self {
        Self::AADManagedIdentity(AADManagedIdentityAuth { client_id: None })
    }

    /// Constructs a new AAD configuration to authenticate with a system-assigned 
    /// or user-assigned managed identity with a specific client id.
    #[cfg(feature="aad")]
    pub fn aad_managed_identity_with_client_id(client_id: impl ToString) -> Self {
        Self::AADManagedIdentity(AADManagedIdentityAuth { client_id: Some(client_id.to_string()) })
    }

    /// Constructs a new AAD service principal configuration.
    #[cfg(feature="aad")]
    pub fn aad_service_principal(client_id: impl ToString, client_secret: impl ToString) -> Self {
        Self::AADServicePrincipal(AADServicePrincipalAuth { 
            client_id: client_id.to_string(), 
            client_secret: client_secret.to_string() 
        })
    }
}
