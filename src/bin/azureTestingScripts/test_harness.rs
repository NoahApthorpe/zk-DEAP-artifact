//This was made with AI Assistance //AE-FIX (7): added, as the Acknowledgments require it and fixture_server.rs already carried one

// AE-FIX: see README.md for the complete list of artifact-evaluation fixes
// applied to this file. Every change is marked with an "AE-FIX (n)" comment.

use serde::{Deserialize, Serialize}; //Serialize/deserialize
use std::collections::{HashMap, BTreeMap}; //Data structures
use std::time::Instant; //Timing
use std::fs::{File, OpenOptions}; //File I/O
use std::io::Write; //Write trait
use clap::Parser; //CLI parsing
use reqwest::blocking::Client; //HTTP client
use base64::Engine; //Base64 encoding
use frost_ristretto255 as frost; //FROST threshold signatures
use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar}; //AE-FIX (12)
use rand::rngs::OsRng; //AE-FIX (12)
use ed25519_dalek::{VerifyingKey, SigningKey}; //Digital signatures

use zk_deap::common::{self, VerifiedCiphertext, VerifiedPartial, PartialDecryption}; //Main library imports
use zk_deap::bulletproof; //Bulletproof ZKP
use zk_deap::snark; //SNARK ZKP
use zk_deap::stark; //STARK ZKP

#[derive(Parser, Debug)]
#[command(author, version, about = "zk-DEAP Test Harness")] //AE-FIX (8): was "ZK-DISPHASIA", a former name for this work
struct Args { #[arg(long, default_value = "http://fixture-server:8080")] fixture_server: String, #[arg(long)] vm_profile: String, #[arg(long)] device_id: u32, #[arg(long, default_value = "/tmp/metrics.jsonl")] output: String } //Command-line arguments

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum ZKPType { Bulletproof, SNARK, STARK } //ZKP type enum

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum TestFunction { DKG1, DKG2, DKG3, PartialGen, PartialVerify, AggCompute, ProofGen, ProofVerify, BaselineRound } //Function being tested (shared + ZKP-specific). AE-FIX (12): BaselineRound added

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestConfig { zkp_type: Option<ZKPType>, function: TestFunction, n: usize, t: usize, device_id: u32, run: usize } //Test configuration (zkp_type is None for shared functions)

// AE-FIX (13): the four component sizes of Table IV, measured from the proof
// this run generated rather than left blank. Raw content bytes, matching the
// paper's convention of 64 B for two 32-byte curve points.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct ProofComponents { elgamal_bytes: usize, schnorr_bytes: usize, zkp_bytes: usize, signature_bytes: usize }

#[derive(Debug, Serialize, Deserialize)]
struct Metrics { timestamp: String, vm_profile: String, vm_arch: String, test_config: TestConfig, status: String, failure_reason: Option<String>, wall_time_us: u128, cpu_time_user_us: u128, cpu_time_system_us: u128, peak_rss_kb: u64, initial_rss_kb: u64, delta_rss_kb: i64, disk_read_kb: u64, disk_write_kb: u64, cycles: Option<u64>, instructions: Option<u64>, cache_misses: Option<u64>, energy_estimate_joules: Option<f64>, output_size_bytes: Option<usize>, proof_components: Option<ProofComponents> } //Performance metrics. AE-FIX (13)

struct FixtureClient { base_url: String, client: Client } //Fixture server client
impl FixtureClient {
    fn new(base_url: String) -> Self { Self { base_url, client: Client::new() } }
    fn get_dkg_completed(&self, n: usize, t: usize, device_id: u32) -> Result<DeviceOutput, String> { let url = format!("{}/api/dkg/completed/{}/{}/{}", self.base_url, n, t, device_id); self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.json().map_err(|e| format!("JSON error: {}", e)) }
    fn get_round1_packages(&self, n: usize, t: usize, device_id: u32) -> Result<Vec<Vec<u8>>, String> { let url = format!("{}/api/dkg/round1/{}/{}/{}", self.base_url, n, t, device_id); let encoded: Vec<String> = self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.json().map_err(|e| format!("JSON error: {}", e))?; encoded.iter().map(|s| base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("Base64 error: {}", e))).collect() }
    fn get_round2_packages(&self, n: usize, t: usize, device_id: u32) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> { let url = format!("{}/api/dkg/round2/{}/{}/{}", self.base_url, n, t, device_id); #[derive(Deserialize)] struct Response { round1_packages: Vec<String>, round2_packages: Vec<String> } let resp: Response = self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.json().map_err(|e| format!("JSON error: {}", e))?; let r1: Result<Vec<_>, _> = resp.round1_packages.iter().map(|s| base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("Base64 error: {}", e))).collect(); let r2: Result<Vec<_>, _> = resp.round2_packages.iter().map(|s| base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("Base64 error: {}", e))).collect(); Ok((r1?, r2?)) }
    fn get_sample_proof(&self, zkp_type: ZKPType, n: usize, t: usize) -> Result<Vec<u8>, String> { let zkp_str = match zkp_type { ZKPType::Bulletproof => "bulletproof", ZKPType::SNARK => "snark", ZKPType::STARK => "stark" }; let url = format!("{}/api/proof/{}/{}/{}", self.base_url, zkp_str, n, t); self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.bytes().map(|b| b.to_vec()).map_err(|e| format!("HTTP error: {}", e)) }
    fn get_ciphertexts(&self, zkp_type: ZKPType, n: usize, t: usize) -> Result<Vec<VerifiedCiphertext>, String> { let zkp_str = match zkp_type { ZKPType::Bulletproof => "bulletproof", ZKPType::SNARK => "snark", ZKPType::STARK => "stark" }; let url = format!("{}/api/ciphertexts/{}/{}/{}", self.base_url, zkp_str, n, t); let encoded: Vec<String> = self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.json().map_err(|e| format!("JSON error: {}", e))?; encoded.iter().map(|s| { let bytes = base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("Base64 error: {}", e))?; bincode::deserialize(&bytes).map_err(|e| format!("Bincode error: {}", e)) }).collect() }
    fn get_sample_partial(&self, zkp_type: ZKPType, n: usize, t: usize) -> Result<VerifiedPartialData, String> { let zkp_str = match zkp_type { ZKPType::Bulletproof => "bulletproof", ZKPType::SNARK => "snark", ZKPType::STARK => "stark" }; let url = format!("{}/api/partial/{}/{}/{}", self.base_url, zkp_str, n, t); self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.json().map_err(|e| format!("JSON error: {}", e)) }
    fn get_threshold_partials(&self, zkp_type: ZKPType, n: usize, t: usize) -> Result<Vec<PartialDecryption>, String> { let zkp_str = match zkp_type { ZKPType::Bulletproof => "bulletproof", ZKPType::SNARK => "snark", ZKPType::STARK => "stark" }; let url = format!("{}/api/partials/{}/{}/{}", self.base_url, zkp_str, n, t); let encoded: Vec<String> = self.client.get(&url).send().map_err(|e| format!("HTTP error: {}", e))?.json().map_err(|e| format!("JSON error: {}", e))?; encoded.iter().map(|s| { let bytes = base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("Base64 error: {}", e))?; bincode::deserialize(&bytes).map_err(|e| format!("Bincode error: {}", e)) }).collect() }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DeviceOutput { device_id: u32, key_package: Vec<u8>, public_package: Vec<u8>, signing_pubkey: [u8; 32], signing_seed: [u8; 32] } //DKG ceremony output for one device. AE-FIX (3): signing_seed added

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VerifiedPartialData { device_id: u32, partial_bytes: Vec<u8>, aggregate_c1_bytes: [u8; 32], aggregate_c2_bytes: [u8; 32] } //Partial with pre-computed aggregate

struct TestRunner { fixture_client: FixtureClient, output_file: File, vm_profile: String, device_id: u32, halo2_setup: Option<snark::Halo2Setup>, peer_keys_cache: HashMap<(usize, usize), HashMap<u32, VerifyingKey>>, last_components: Option<ProofComponents> } //Main test runner with caching. AE-FIX (13)
impl TestRunner {
    fn new(args: &Args) -> Result<Self, Box<dyn std::error::Error>> { let halo2_setup = if std::path::Path::new("./trusted_setup/kzg_bn254_8.params").exists() /* AE-FIX (1): was kzg_bn254_5.params; snark::PARAMS_PATH is kzg_bn254_8.params, so this gate never passed and every SNARK test failed */ { println!("Loading Halo2 setup..."); Some(snark::setup_halo2()?) } else { println!("Warning: Halo2 params not found, SNARK tests will fail"); None }; let output_file = OpenOptions::new().create(true).append(true).open(&args.output)?; Ok(Self { fixture_client: FixtureClient::new(args.fixture_server.clone()), output_file, vm_profile: args.vm_profile.clone(), device_id: args.device_id, halo2_setup, peer_keys_cache: HashMap::new(), last_components: None }) }
    fn get_cached_peer_keys(&mut self, n: usize, t: usize) -> Result<HashMap<u32, VerifyingKey>, Box<dyn std::error::Error>> { if let Some(cached) = self.peer_keys_cache.get(&(n, t)) { return Ok(cached.clone()); } let mut peer_keys = HashMap::new(); for i in 1..=n { let dev_out = self.fixture_client.get_dkg_completed(n, t, i as u32)?; let vk = VerifyingKey::from_bytes(&dev_out.signing_pubkey)?; peer_keys.insert(i as u32, vk); } self.peer_keys_cache.insert((n, t), peer_keys.clone()); Ok(peer_keys) } //Fetch and cache peer signing keys
    fn run_all_tests(&mut self) { //Run all tests with optimized structure (shared functions once, ZKP-specific per type)
        // AE-FIX (6): the sweep can be narrowed from the environment so that a
        // reviewer can do a fast partial run. Defaults are the original values.
        //   ZKDEAP_SIZES=5,10,20  ZKDEAP_RATIOS=0.5
        let network_sizes = env_list_usize("ZKDEAP_SIZES", &[5, 10, 20, 50, 100, 250, 500]);
        let threshold_ratios = env_list_f64("ZKDEAP_RATIOS", &[0.25, 0.5, 0.67, 0.75]);
        let network_scaled_functions = vec![TestFunction::PartialGen, TestFunction::AggCompute, TestFunction::DKG1, TestFunction::DKG2, TestFunction::DKG3, TestFunction::BaselineRound]; // Functions that scale with network. AE-FIX (12)
        let zkp_functions = vec![TestFunction::ProofGen, TestFunction::ProofVerify]; // ZKP-specific functions (test once per type)
        let zkp_types = vec![ZKPType::Bulletproof, ZKPType::SNARK, ZKPType::STARK];

        let mut test_count = 0;
        let total_tests = (network_sizes.len() * threshold_ratios.len() * network_scaled_functions.len() * 30) + (30) + (zkp_types.len() * zkp_functions.len() * 30);
        println!("=== Starting Test Suite ===\nVM Profile: {}\nTotal tests to run: {}\n", self.vm_profile, total_tests);

        let mut success_count = 0; let mut failure_count = 0;

        println!("\nTesting PartialVerify (single config)..."); // Test PartialVerify once
        let n = 5; let t = 3;
        for run in 1..=30 {
            test_count += 1;
            let config = TestConfig { zkp_type: None, function: TestFunction::PartialVerify, n, t, device_id: self.device_id, run };
            println!("[{}/{}] PartialVerify n={} t={} run={}", test_count, total_tests, n, t, run);
            match self.run_single_test(&config) {
                Ok(metrics) => {
                    self.write_metrics(&metrics);
                    if metrics.status == "SUCCESS" { success_count += 1; } else { failure_count += 1; }
                }
                Err(e) => { eprintln!("  Error: {}", e); failure_count += 1; }
            }
        }

        println!("\nTesting ZKP-specific functions (ProofGen, ProofVerify) per ZKP type..."); // Test ZKP-specific functions once per type
        let n = 5; let t = 3;
        for zkp_type in &zkp_types { 
            println!("\n--- Testing {:?} ---", zkp_type); 
            for function in &zkp_functions { 
                for run in 1..=30 { 
                    test_count += 1; 
                    let config = TestConfig { zkp_type: Some(*zkp_type), function: *function, n, t, device_id: self.device_id, run }; 
                    println!("[{}/{}] {:?} {:?} n={} t={} run={}", test_count, total_tests, zkp_type, function, n, t, run); 
                    match self.run_single_test(&config) { 
                        Ok(metrics) => { 
                            self.write_metrics(&metrics); 
                            if metrics.status == "SUCCESS" { success_count += 1; } else { failure_count += 1; } 
                        } 
                        Err(e) => { eprintln!("  Error: {}", e); failure_count += 1; } 
                    } 
                } 
            } 
        }

        println!("Testing network-scaled functions (DKG, PartialGen, Aggregate)..."); // Test network-scaled functions
        for function in &network_scaled_functions { 
            for n in &network_sizes { 
                for t_ratio in &threshold_ratios { 
                    let t = (*n as f64 * t_ratio).ceil() as usize; 
                    for run in 1..=30 { 
                        test_count += 1; 
                        let config = TestConfig { zkp_type: None, function: *function, n: *n, t, device_id: self.device_id, run }; 
                        println!("[{}/{}] {:?} n={} t={} run={}", test_count, total_tests, function, n, t, run); 
                        match self.run_single_test(&config) { 
                            Ok(metrics) => { 
                                self.write_metrics(&metrics); 
                                if metrics.status == "SUCCESS" { success_count += 1; } else { failure_count += 1; } 
                            } 
                            Err(e) => { eprintln!("  Error: {}", e); failure_count += 1; } 
                        } 
                    } 
                } 
            } 
        }

        println!("\n=== Test Suite Complete ===\nTotal tests: {}\nSuccesses: {}\nFailures: {}\nSuccess rate: {:.1}%", test_count, success_count, failure_count, (success_count as f64 / test_count as f64) * 100.0);
    }
    fn run_single_test(&mut self, config: &TestConfig) -> Result<Metrics, Box<dyn std::error::Error>> { //Run a single test with full instrumentation
        if config.run <= 2 { let _ = self.run_function(config); let _ = self.run_function(config); std::thread::sleep(std::time::Duration::from_millis(10)); } //Warm up CPU caches and JIT
        // AE-FIX (2): the timer used to start here and span all of run_function,
        // which performs fixture-server HTTP GETs before the cryptographic work.
        // Measured against the shipped logs, that network latency was 52-96% of
        // every fast operation. Each test_* function now times only its own
        // "MEASURED OPERATION" and returns the duration.
        // AE-FIX (4): CPU time is now a before/after delta over the operation.
        // Previously the cumulative process counter was recorded as if it were a
        // per-operation value (it is monotonically non-decreasing).
        // AE-FIX (10): these four probes read /proc, which does not exist on macOS
        // and may be restricted in containers. Previously each was propagated with
        // `?`, so an unavailable *diagnostic* counter aborted the cryptographic
        // measurement itself -- on a non-Linux host every single test recorded
        // "No such file or directory". They now degrade to 0 instead.
        let initial_rss = Self::get_rss_kb().unwrap_or(0); let cpu_before = Self::get_cpu_times().unwrap_or((0, 0)); let result = self.run_function(config); let wall_time_us = match &result { Ok((us, _)) => *us, Err(_) => 0 };
        let peak_rss = Self::get_peak_rss_kb().unwrap_or(0); let delta_rss = peak_rss as i64 - initial_rss as i64; let cpu_after = Self::get_cpu_times().unwrap_or((0, 0)); let (user_time_us, system_time_us) = (cpu_after.0.saturating_sub(cpu_before.0), cpu_after.1.saturating_sub(cpu_before.1)); let (disk_read_kb, disk_write_kb) = Self::get_io_stats().unwrap_or((0, 0)); //AE-FIX (10)
        // AE-FIX (4): cycles and energy are no longer reported. They were derived
        // from cumulative CPU time multiplied by a hardcoded 2.5 GHz, which matched
        // none of the SKUs actually used (2.1-2.6 GHz), so neither was a measurement.
        // instructions and cache_misses were already null in every row because
        // get_hardware_counters() is an unimplemented stub.
        let metrics = Metrics { timestamp: Self::timestamp_iso8601(), vm_profile: self.vm_profile.clone(), vm_arch: std::env::consts::ARCH.to_string(), test_config: config.clone(), status: if result.is_ok() { "SUCCESS".to_string() } else { "FAILED".to_string() }, failure_reason: result.as_ref().err().map(|e| e.to_string()), wall_time_us, cpu_time_user_us: user_time_us, cpu_time_system_us: system_time_us, peak_rss_kb: peak_rss, initial_rss_kb: initial_rss, delta_rss_kb: delta_rss, disk_read_kb, disk_write_kb, cycles: None, instructions: None, cache_misses: None, energy_estimate_joules: None, output_size_bytes: result.as_ref().ok().map(|(_, sz)| *sz), proof_components: self.last_components.take() };
        // AE-FIX (4): removed the get_hardware_counters() call. The function is a
        // stub that always returns Err, so this branch never executed.
        Ok(metrics)
    }
    fn run_function(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //Route to the appropriate test function. AE-FIX (2): returns (measured_us, output_size)
        match config.function { TestFunction::DKG1 => self.test_dkg_phase1(config), TestFunction::DKG2 => self.test_dkg_phase2(config), TestFunction::DKG3 => self.test_dkg_phase3(config), TestFunction::PartialGen => self.test_partial_generation(config), TestFunction::PartialVerify => self.test_partial_verification(config), TestFunction::AggCompute => self.test_aggregate_computation(config), TestFunction::ProofGen => self.test_proof_generation(config), TestFunction::ProofVerify => self.test_proof_verification(config), TestFunction::BaselineRound => self.test_baseline_round(config) }
    }
    fn test_dkg_phase1(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { let t0 = Instant::now(); let (_secret_pkg, round1_pkg) = common::dkg_phase1(config.device_id, config.n, config.t)?; let us = t0.elapsed().as_micros(); /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */ let size = bincode::serialize(&round1_pkg)?.len(); Ok((us, size)) } //DKG Phase 1 (uses common module directly)
    fn test_dkg_phase2(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //DKG Phase 2 (uses common module directly)
        let r1_packages_bytes = self.fixture_client.get_round1_packages(config.n, config.t, config.device_id)?; //Get fixtures
        let mut received_r1 = BTreeMap::new(); let all_ids: Vec<u16> = (1..=config.n as u16).filter(|&id| id != config.device_id as u16).collect(); //Deserialize round1 packages
        for (i, pkg_bytes) in r1_packages_bytes.iter().enumerate() { let pkg = frost::keys::dkg::round1::Package::deserialize(&pkg_bytes[..])?; let id = frost::Identifier::try_from(all_ids[i])?; received_r1.insert(id, pkg); }
        let (secret_pkg, _) = common::dkg_phase1(config.device_id, config.n, config.t)?; //Get our secret package (from phase 1)
        let t0 = Instant::now(); let (_round2_secret, round2_packages) = common::dkg_phase2(secret_pkg, &received_r1)?; let us = t0.elapsed().as_micros(); //MEASURED OPERATION /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */
        let size = round2_packages.values().map(|pkg| bincode::serialize(pkg).unwrap_or_default().len()).sum(); Ok((us, size)) //Return total size of round2 packages
    }
    fn test_dkg_phase3(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //DKG Phase 3 (uses common module directly)
        let (r1_packages_bytes, r2_packages_bytes) = self.fixture_client.get_round2_packages(config.n, config.t, config.device_id)?; //Get fixtures
        let all_ids: Vec<u16> = (1..=config.n as u16).filter(|&id| id != config.device_id as u16).collect(); //Deserialize packages
        let mut received_r1 = BTreeMap::new(); for (i, pkg_bytes) in r1_packages_bytes.iter().enumerate() { let pkg = frost::keys::dkg::round1::Package::deserialize(&pkg_bytes[..])?; let id = frost::Identifier::try_from(all_ids[i])?; received_r1.insert(id, pkg); }
        let mut received_r2 = BTreeMap::new(); for (i, pkg_bytes) in r2_packages_bytes.iter().enumerate() { let pkg = frost::keys::dkg::round2::Package::deserialize(&pkg_bytes[..])?; let id = frost::Identifier::try_from(all_ids[i])?; received_r2.insert(id, pkg); }
        let (secret_pkg, _) = common::dkg_phase1(config.device_id, config.n, config.t)?; let (round2_secret, _) = common::dkg_phase2(secret_pkg, &received_r1)?; //Get round2 secret (from phase 2)
        let t0 = Instant::now(); let (key_package, public_package) = common::dkg_phase3(&round2_secret, &received_r1, &received_r2)?; let us = t0.elapsed().as_micros(); //MEASURED OPERATION /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */
        let size = bincode::serialize(&key_package)?.len() + bincode::serialize(&public_package)?.len(); Ok((us, size)) //Return size of key package
    }
    fn test_partial_generation(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //Partial Generation (uses common module directly)
        let device_output = self.fixture_client.get_dkg_completed(config.n, config.t, config.device_id)?; //Get DKG outputs (not measured)
        let key_package = frost::keys::KeyPackage::deserialize(&device_output.key_package).map_err(|e| format!("KeyPackage deser: {:?}", e))?;
        let public_package = frost::keys::PublicKeyPackage::deserialize(&device_output.public_package).map_err(|e| format!("PublicPackage deser: {:?}", e))?;
        // AE-FIX (3): was SigningKey::from_bytes(&device_output.signing_pubkey), which
        // builds a *signing* key from a *verifying* key's bytes. The resulting
        // signatures could never verify against the peer key map. The fixture server
        // now serves the seed it derived the key from (see fixture_server.rs AE-FIX 3).
        let signing_key = SigningKey::from_bytes(&device_output.signing_seed); //Get signing key
        let ciphertexts = self.fixture_client.get_ciphertexts(ZKPType::Bulletproof, config.n, config.t)?; //Get verified ciphertexts (use any ZKP type, they're all the same)
        let t0 = Instant::now(); let partial = common::generate_partial_decryption(config.device_id, &key_package, &public_package, &signing_key, &ciphertexts)?; let us = t0.elapsed().as_micros(); //MEASURED OPERATION /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */
        let size = bincode::serialize(&partial)?.len(); Ok((us, size))
    }
    fn test_partial_verification(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //Partial Verification (uses common module directly)
        let partial_data = self.fixture_client.get_sample_partial(ZKPType::Bulletproof, config.n, config.t)?; //Get fixtures
        let partial: PartialDecryption = bincode::deserialize(&partial_data.partial_bytes)?;
        let device_output = self.fixture_client.get_dkg_completed(config.n, config.t, config.device_id)?;
        let public_package = frost::keys::PublicKeyPackage::deserialize(&device_output.public_package).map_err(|e| format!("PublicPackage deser: {:?}", e))?;
        let peer_keys = self.get_cached_peer_keys(config.n, config.t)?; //Get peer keys (all devices)
        let ciphertexts = self.fixture_client.get_ciphertexts(ZKPType::Bulletproof, config.n, config.t)?;
        let mut verified_partials = Vec::new(); let mut rates = HashMap::new();
        let t0 = Instant::now(); let verified = common::receive_partial(partial, &peer_keys, &public_package, &ciphertexts, &mut verified_partials, &mut rates)?; let us = t0.elapsed().as_micros(); //MEASURED OPERATION /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */
        Ok((us, std::mem::size_of_val(&verified)))
    }
    fn test_aggregate_computation(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //Aggregate Computation (uses common module directly)
        let ciphertexts = self.fixture_client.get_ciphertexts(ZKPType::Bulletproof, config.n, config.t)?; //Get fixtures
        let partial_decryptions = self.fixture_client.get_threshold_partials(ZKPType::Bulletproof, config.n, config.t)?;
        let verified_partials: Vec<VerifiedPartial> = partial_decryptions.iter().map(|p| VerifiedPartial { device_id: p.device_id, timestamp: p.timestamp, partial: p.partial.0.decompress().unwrap() }).collect(); //Convert to VerifiedPartial
        let t0 = Instant::now(); let (count, total) = common::compute_aggregate(config.t, &ciphertexts, &verified_partials)?; let us = t0.elapsed().as_micros(); //MEASURED OPERATION /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */
        println!("  Result: {}/{}", count, total); Ok((us, std::mem::size_of::<(usize, usize)>()))
    }
    // AE-FIX (12): an unverified-aggregation round, i.e. the same HE and threshold
    // stack with ZKP generation and verification disabled. Section V-C compares
    // against this, but nothing in the original harness measured it, so the
    // Baseline column of Table III had no measured counterpart.
    fn test_baseline_round(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> {
        let device_output = self.fixture_client.get_dkg_completed(config.n, config.t, config.device_id)?; //Get fixtures (not timed)
        let key_package = frost::keys::KeyPackage::deserialize(&device_output.key_package).map_err(|e| format!("KeyPackage deser: {:?}", e))?;
        let public_package = frost::keys::PublicKeyPackage::deserialize(&device_output.public_package).map_err(|e| format!("PublicPackage deser: {:?}", e))?;
        let signing_key = SigningKey::from_bytes(&device_output.signing_seed);
        let peer_keys = self.get_cached_peer_keys(config.n, config.t)?;
        let ciphertexts = self.fixture_client.get_ciphertexts(ZKPType::Bulletproof, config.n, config.t)?;
        let partial_data = self.fixture_client.get_sample_partial(ZKPType::Bulletproof, config.n, config.t)?;
        let peer_partial: PartialDecryption = bincode::deserialize(&partial_data.partial_bytes)?;
        let partial_decryptions = self.fixture_client.get_threshold_partials(ZKPType::Bulletproof, config.n, config.t)?;
        let verified_partials: Vec<VerifiedPartial> = partial_decryptions.iter().map(|p| VerifiedPartial { device_id: p.device_id, timestamp: p.timestamp, partial: p.partial.0.decompress().unwrap() }).collect();
        let h = common::frost_to_point(&public_package.verifying_key())?;
        let t0 = Instant::now(); //MEASURED OPERATION: one round for this participant, no proofs
        let r = Scalar::random(&mut OsRng); //encrypt own input under lifted ElGamal
        let _c1 = RISTRETTO_BASEPOINT_POINT * r;
        let _c2 = RISTRETTO_BASEPOINT_POINT * Scalar::from(1u64) + h * r;
        let _own = common::generate_partial_decryption(config.device_id, &key_package, &public_package, &signing_key, &ciphertexts)?; //own partial decryption
        for _ in 0..config.t { //verify the threshold's partials
            let mut vp: Vec<VerifiedPartial> = Vec::new();
            let mut rates: HashMap<u32, (u64, u32)> = HashMap::new();
            common::receive_partial(peer_partial.clone(), &peer_keys, &public_package, &ciphertexts, &mut vp, &mut rates)?;
        }
        common::compute_aggregate(config.t, &ciphertexts, &verified_partials)?; //combine and extract
        let us = t0.elapsed().as_micros();
        Ok((us, 0))
    }
    fn test_proof_generation(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //Proof Generation (ZKP-specific)
        let zkp_type = config.zkp_type.ok_or("ZKP type required for ProofGen")?;
        let device_output = self.fixture_client.get_dkg_completed(config.n, config.t, config.device_id)?; //Get DKG outputs
        let key_package = frost::keys::KeyPackage::deserialize(&device_output.key_package).map_err(|e| format!("KeyPackage deser: {:?}", e))?;
        let public_package = frost::keys::PublicKeyPackage::deserialize(&device_output.public_package).map_err(|e| format!("PublicPackage deser: {:?}", e))?;
        let peer_keys = self.get_cached_peer_keys(config.n, config.t)?; //Get peer keys
        let state = 1u8; //Test with state=1
        // AE-FIX (2): timer covers only the measured operation, not the fixture
        // fetches above. AE-FIX (13): it now also stops before serialization and
        // the component measurement, neither of which is proof generation.
        let t0 = Instant::now();
        let (us, proof_bytes, comps) = match zkp_type { //MEASURED OPERATION (ZKP-specific)
            ZKPType::Bulletproof => {
                let device = bulletproof::IoTDevice::new(config.device_id, config.t, key_package, public_package, peer_keys, None)?;
                let proof = device.generate_proof(state)?;
                let us = t0.elapsed().as_micros();
                let e = &proof.elgamal_proof;
                let comps = ProofComponents {
                    elgamal_bytes: proof.elgamal_c1.0.as_bytes().len() + proof.elgamal_c2.0.as_bytes().len(),
                    schnorr_bytes: e.commit_r.0.as_bytes().len() + e.commit_s.0.as_bytes().len() + e.commit_c.0.as_bytes().len()
                        + e.resp_r.0.to_bytes().len() + e.resp_state.0.to_bytes().len() + e.state_commit.0.as_bytes().len()
                        + proof.nonce.len(),
                    zkp_bytes: proof.bulletproof.len(),
                    signature_bytes: proof.signature.len() };
                (us, bincode::serialize(&proof)?, comps)
            }
            ZKPType::SNARK => {
                let setup = self.halo2_setup.as_ref().ok_or("Halo2 setup not loaded")?;
                let device = snark::IoTDevice::new(config.device_id, config.t, key_package, public_package, peer_keys, setup.clone(), None)?;
                let proof = device.generate_proof(state)?;
                let us = t0.elapsed().as_micros();
                let e = &proof.elgamal_proof;
                let comps = ProofComponents {
                    elgamal_bytes: proof.elgamal_c1.0.as_bytes().len() + proof.elgamal_c2.0.as_bytes().len(),
                    schnorr_bytes: e.commit_r.0.as_bytes().len() + e.commit_s.0.as_bytes().len() + e.commit_p.0.as_bytes().len()
                        + e.resp_r.0.to_bytes().len() + e.resp_state.0.to_bytes().len() + e.pedersen_commit.0.as_bytes().len()
                        + proof.v_commit.len() + proof.resp_f.len() + proof.c_f.len() + 1,
                    zkp_bytes: proof.halo2_proof.len(),
                    signature_bytes: proof.signature.len() };
                (us, bincode::serialize(&proof)?, comps)
            }
            ZKPType::STARK => {
                let device = stark::IoTDevice::new(config.device_id, config.t, key_package, public_package, peer_keys, None)?;
                let proof = device.generate_proof(state)?;
                let us = t0.elapsed().as_micros();
                let e = &proof.elgamal_proof;
                let comps = ProofComponents {
                    elgamal_bytes: proof.elgamal_c1.0.as_bytes().len() + proof.elgamal_c2.0.as_bytes().len(),
                    schnorr_bytes: e.commit_r.0.as_bytes().len() + e.commit_s.0.as_bytes().len() + e.commit_p.0.as_bytes().len()
                        + e.resp_r.0.to_bytes().len() + e.resp_state.0.to_bytes().len() + e.pedersen_commit.0.as_bytes().len()
                        + proof.v_commit.len() + proof.resp_f.len() + proof.c_f.len() + 1,
                    zkp_bytes: proof.stark_proof.len(),
                    signature_bytes: proof.signature.len() };
                (us, bincode::serialize(&proof)?, comps)
            }
        };
        self.last_components = Some(comps);
        Ok((us, proof_bytes.len()))
    }
    fn test_proof_verification(&mut self, config: &TestConfig) -> Result<(u128, usize), Box<dyn std::error::Error>> { //Proof Verification (ZKP-specific)
        let zkp_type = config.zkp_type.ok_or("ZKP type required for ProofVerify")?;
        let proof_bytes = self.fixture_client.get_sample_proof(zkp_type, config.n, config.t)?; //Get sample proof from fixture server
        let device_output = self.fixture_client.get_dkg_completed(config.n, config.t, config.device_id)?; //Get DKG outputs
        let key_package = frost::keys::KeyPackage::deserialize(&device_output.key_package).map_err(|e| format!("KeyPackage deser: {:?}", e))?;
        let public_package = frost::keys::PublicKeyPackage::deserialize(&device_output.public_package).map_err(|e| format!("PublicPackage deser: {:?}", e))?;
        let peer_keys = self.get_cached_peer_keys(config.n, config.t)?; //Get peer keys
        let t0 = Instant::now(); //MEASURED OPERATION starts here /* AE-FIX (2): timer covers only the measured operation, not the fixture fetches above */
        match zkp_type { //MEASURED OPERATION (ZKP-specific)
            ZKPType::Bulletproof => { let mut device = bulletproof::IoTDevice::new(config.device_id, config.t, key_package, public_package, peer_keys, None)?; let proof: bulletproof::DeviceProof = bincode::deserialize(&proof_bytes)?; device.receive_proof(proof)?; }
            ZKPType::SNARK => { let setup = self.halo2_setup.as_ref().ok_or("Halo2 setup not loaded")?; let mut device = snark::IoTDevice::new(config.device_id, config.t, key_package, public_package, peer_keys, setup.clone(), None)?; let proof: snark::DeviceProof = bincode::deserialize(&proof_bytes)?; device.receive_proof(proof)?; }
            ZKPType::STARK => { let mut device = stark::IoTDevice::new(config.device_id, config.t, key_package, public_package, peer_keys, None)?; let proof: stark::DeviceProof = bincode::deserialize(&proof_bytes)?; device.receive_proof(proof)?; }
        }
        let us = t0.elapsed().as_micros();
        Ok((us, proof_bytes.len()))
    }
    fn get_rss_kb() -> Result<u64, Box<dyn std::error::Error>> { let pid = std::process::id(); let status = std::fs::read_to_string(format!("/proc/{}/status", pid))?; for line in status.lines() { if line.starts_with("VmRSS:") { let kb: u64 = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0); return Ok(kb); } } Ok(0) } //Get current RSS memory
    fn get_peak_rss_kb() -> Result<u64, Box<dyn std::error::Error>> { let pid = std::process::id(); let status = std::fs::read_to_string(format!("/proc/{}/status", pid))?; for line in status.lines() { if line.starts_with("VmHWM:") { let kb: u64 = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0); return Ok(kb); } } Ok(0) } //Get peak RSS memory
    fn get_cpu_times() -> Result<(u128, u128), Box<dyn std::error::Error>> { //Read /proc/self/stat for CPU times
        let pid = std::process::id(); let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid))?; let parts: Vec<&str> = stat.split_whitespace().collect(); //Parse the stat file (format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime ...)
        if parts.len() < 15 { return Ok((0, 0)); }
        let utime_ticks: u64 = parts[13].parse().unwrap_or(0); let stime_ticks: u64 = parts[14].parse().unwrap_or(0); //utime is at index 13, stime is at index 14 (in clock ticks)
        // AE-FIX (5): was hardcoded to 100. That is the common default, not a guarantee.
        let clock_ticks_per_sec = { unsafe extern "C" { fn sysconf(name: i32) -> i64; } let v = unsafe { sysconf(2) }; if v > 0 { v as u64 } else { 100 } }; //_SC_CLK_TCK == 2 on Linux
        let utime_us = (utime_ticks * 1_000_000) / clock_ticks_per_sec; let stime_us = (stime_ticks * 1_000_000) / clock_ticks_per_sec; //Convert from clock ticks to microseconds
        Ok((utime_us as u128, stime_us as u128))
    }
    fn get_io_stats() -> Result<(u64, u64), Box<dyn std::error::Error>> { //Read /proc/self/io (may fail on some systems)
        let pid = std::process::id();
        match std::fs::read_to_string(format!("/proc/{}/io", pid)) { Ok(io_str) => { let mut read_bytes = 0u64; let mut write_bytes = 0u64; for line in io_str.lines() { if line.starts_with("read_bytes:") { read_bytes = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0); } else if line.starts_with("write_bytes:") { write_bytes = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0); } } Ok((read_bytes / 1024, write_bytes / 1024)) } Err(_) => Ok((0, 0)) } //If /proc/self/io is not available, return zeros
    }
    // AE-FIX (4): retained unchanged for reference, but no longer called. It
    // always returns Err, which is why `instructions` and `cache_misses` were
    // null in all 26,460 rows of the original logs.
    #[allow(dead_code)]
    fn get_hardware_counters() -> Result<(u64, u64, u64), Box<dyn std::error::Error>> { //Try to use 'perf stat' to get hardware counters (may not work on all VMs, especially ARM or restricted environments)
        use std::process::Command;
        let perf_check = Command::new("which").arg("perf").output(); //Check if perf is available
        if perf_check.is_err() || !perf_check.unwrap().status.success() { return Err("perf not available".into()); } //perf not available
        Err("Hardware counters require manual perf setup".into()) //Note: This is tricky because we'd need to attach perf to our own process. For now, we'll return an error and let the caller handle it gracefully. Alternative: Use 'perf_event_open' syscall directly, but that requires unsafe code
    }
    fn timestamp_iso8601() -> String { chrono::Utc::now().to_rfc3339() } //Get ISO8601 timestamp
    fn write_metrics(&mut self, metrics: &Metrics) { let json = serde_json::to_string(metrics).unwrap(); writeln!(self.output_file, "{}", json).ok(); self.output_file.flush().ok(); } //Write metrics to JSONL file
}

// AE-FIX (6): shared environment-override helpers. Kept deliberately small.
fn env_list_usize(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) { Ok(v) if !v.trim().is_empty() => v.split(',').filter_map(|x| x.trim().parse().ok()).collect(), _ => default.to_vec() }
}
fn env_list_f64(key: &str, default: &[f64]) -> Vec<f64> {
    match std::env::var(key) { Ok(v) if !v.trim().is_empty() => v.split(',').filter_map(|x| x.trim().parse().ok()).collect(), _ => default.to_vec() }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("=== zk-DEAP Test Harness ===\nVM Profile: {}\nDevice ID: {}\nFixture Server: {}\nOutput: {}\n", args.vm_profile, args.device_id, args.fixture_server, args.output);
    let mut runner = TestRunner::new(&args)?;
    runner.run_all_tests();
    println!("\n=== Test harness completed ===");
    Ok(())
}
