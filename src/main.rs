mod eclipse;
mod find_node;

use serde::de::DeserializeOwned;
use serde::Serialize;
use testground::client::Client;
use testground::network_conf::{
    FilterAction, LinkShape, NetworkConfiguration, RoutingPolicyType, DEFAULT_DATA_NETWORK,
};
use std::net::{Ipv4Addr, IpAddr};
use ipnetwork::Ipv4Network;
use tokio_stream::StreamExt;

const STATE_NETWORK_CONFIGURED: &str = "state_network_configured";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new_and_init().await?;

    // Enable tracing.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .expect("EnvFilter");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    // ////////////////////////
    // Configure network
    // ////////////////////////
    let network_configuration = NetworkConfiguration {
            network: DEFAULT_DATA_NETWORK.to_owned(),
            ipv4: None,
            ipv6: None,
            enable: true,
            default: LinkShape {
                latency: client
                    .run_parameters()
                    .test_instance_params
                    .get("latency")
                    .ok_or("latency is not specified")?
                    .parse::<u64>()?
                    * 1_000_000, // Translate from millisecond to nanosecond
                jitter: 0,
                bandwidth: 1048576, // 1Mib
                filter: FilterAction::Accept,
                loss: 0.0,
                corrupt: 0.0,
                corrupt_corr: 0.0,
                reorder: 0.0,
                reorder_corr: 0.0,
                duplicate: 0.0,
                duplicate_corr: 0.0,
            },
            rules: None,
            callback_state: "None".to_owned(),
            callback_target: None,
            routing_policy: RoutingPolicyType::AllowAll,
        };
    let mut network_configuration_new = NetworkConfiguration {
            network: DEFAULT_DATA_NETWORK.to_owned(),
            ipv4: None,
            ipv6: None,
            enable: true,
            default: LinkShape {
                latency: client
                    .run_parameters()
                    .test_instance_params
                    .get("latency")
                    .ok_or("latency is not specified")?
                    .parse::<u64>()?
                    * 1_000_000, // Translate from millisecond to nanosecond
                jitter: 0,
                bandwidth: 1048576, // 1Mib
                filter: FilterAction::Accept,
                loss: 0.0,
                corrupt: 0.0,
                corrupt_corr: 0.0,
                reorder: 0.0,
                reorder_corr: 0.0,
                duplicate: 0.0,
                duplicate_corr: 0.0,
            },
            rules: None,
            callback_state: STATE_NETWORK_CONFIGURED.to_owned(),
            callback_target: None,
            routing_policy: RoutingPolicyType::AllowAll,
        };
    client.configure_network(network_configuration).await?;
    let current_ipaddr = client.run_parameters().data_network_ip()?.expect("IP address for the data network");
    match current_ipaddr {
        IpAddr::V4(ipv4) => {
                             let ip_vec: [u8; 4] = ipv4.octets();
                             network_configuration_new.ipv4 = Some(Ipv4Network::new(
                                Ipv4Addr::new(ip_vec[0], ip_vec[1], client.group_seq() as u8, ip_vec[3]), 24)
                                    .unwrap()
                                );
                             }
        IpAddr::V6(_ipv6) => { (); }
    }
    client.configure_network(network_configuration_new).await?;

    client
        .barrier(
            STATE_NETWORK_CONFIGURED,
            client.run_parameters().test_instance_count,
        )
        .await?;

    // //////////////////////////////////////////////////////////////
    // Run test case
    // //////////////////////////////////////////////////////////////
    match client.run_parameters().test_case.clone().as_str() {
        "find-node" => find_node::find_node(client.clone()).await?,
        "eclipse-attack-monopolizing-by-incoming-nodes" => {
            eclipse::MonopolizingByIncomingNodes::new()
                .run(client.clone())
                .await?
        }
        _ => unreachable!(),
    };

    Ok(())
}

async fn publish_and_collect<T: Serialize + DeserializeOwned>(
    client: &Client,
    info: T,
) -> Result<Vec<T>, Box<dyn std::error::Error>> {
    const TOPIC: &str = "publish_and_collect";

    client.publish(TOPIC, serde_json::to_string(&info)?).await?;

    let mut stream = client.subscribe(TOPIC).await;

    let mut vec: Vec<T> = vec![];

    for _ in 0..client.run_parameters().test_instance_count {
        match stream.next().await {
            Some(Ok(other)) => {
                let info: T = serde_json::from_str(&other)?;
                vec.push(info);
            }
            Some(Err(e)) => return Err(Box::new(e)),
            None => unreachable!(),
        }
    }

    Ok(vec)
}
