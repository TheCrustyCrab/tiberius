//! Use Azure Active Directory Service Principal authentication.
//!
//! To Setup:
//! - Follow this [link](https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell) to setup your Azure SQL with AAD auth;
//! - Create an AAD Service Principal [link](https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-service-principal?view=azuresql) and configure it to access your SQL instance;
//! - Setup the environment variables with:
//!   - CLIENT_ID: service principal ID;
//!   - CLIENT_SECRET: service principal secret;
//!   - SERVER: SQL server URI
use std::env;
use tiberius::{AuthMethod, Client, Config, Query};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID environment variable.");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET environment variable.");
    let server = env::var("SERVER").expect("Missing SERVER environment variable.");
    let mut config = Config::new();
    config.authentication(AuthMethod::aad_service_principal(client_id, client_secret));
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
