//! Use Azure Active Directory Managed Identity authentication.
//!
//! To Setup:
//! - Enable a system-assigned or user-assigned managed identity on an Azure resource (Virtual Machine, Container Apps, App Service, ...).
//! - Create the user "FROM EXTERNAL PROVIDER" on the SQL database and assign the necessary roles.
//! - See the following tutorial for virtual machines: [link](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/tutorial-windows-vm-access-sql).
//! - Assign the server hostname to the environment variable 'SERVER'.
use std::env;
use tiberius::{AuthMethod, Client, Config, Query};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = env::var("SERVER").expect("Missing SERVER environment variable.");
    let mut config = Config::new();
    config.authentication(AuthMethod::aad_managed_identity());
    config.host(server);
    config.trust_cert();

    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let mut client = Client::connect(config, tcp.compat_write()).await?;
    let params = vec![String::from("foo"), String::from("bar")];
    let mut select = Query::new("SELECT @P1, @P2, @P3");

    for param in params.into_iter() {
        select.bind(param);
    }

    let _res = select.query(&mut client).await?;

    Ok(())
}
