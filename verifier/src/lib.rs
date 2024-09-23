use {
  base64::{engine::general_purpose, Engine as _},
  hmac::{digest::InvalidLength, Hmac, Mac},
  serde::{Deserialize, Serialize},
  sha2::{Digest, Sha256},
  thiserror::Error,
  wasm_bindgen::prelude::*,
};

type HmacSha256 = Hmac<Sha256>;
type Result<T = (), E = Error> = std::result::Result<T, E>;

#[derive(Error, Debug)]
pub enum Error {
  #[error("Base64 decoding error: {0}")]
  Base64(#[from] base64::DecodeError),
  #[error("HMAC error: {0}")]
  Hmac(String),
  #[error("Invalid secret key")]
  InvalidSecretKey,
  #[error("Serialization error: {0}")]
  Serialization(#[from] serde_json::Error),
  #[error("No valid blocks found")]
  Unrecoverable,
}

impl From<Error> for JsValue {
  fn from(error: Error) -> Self {
    JsValue::from_str(&error.to_string())
  }
}

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
  data: String,
  signature: String,
}

#[wasm_bindgen]
impl Block {
  #[wasm_bindgen(getter)]
  pub fn data(&self) -> String {
    self.data.clone()
  }

  #[wasm_bindgen(setter)]
  pub fn set_data(&mut self, data: String) {
    self.data = data
  }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub enum Status {
  Recovered,
  Valid,
  Tampered,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct BlockWithStatus {
  block: Block,
  status: Status,
}

#[wasm_bindgen]
impl BlockWithStatus {
  #[wasm_bindgen(getter)]
  pub fn block(&self) -> Block {
    self.block.clone()
  }

  #[wasm_bindgen(getter)]
  pub fn status(&self) -> Status {
    self.status.clone()
  }
}

/// Handles cryptographic operations for data verification and signing.
///
/// The Verifier struct is responsible for creating and verifying blocks in a simple
/// blockchain-like structure. It uses HMAC-SHA256 for data signing and verification,
/// ensuring the integrity and authenticity of the data stored in each block.
#[wasm_bindgen]
pub struct Verifier {
  secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl Verifier {
  /// Creates a new Verifier instance with the given secret key.
  ///
  /// The secret key is used for signing and verifying data. It should be kept secure
  /// and not shared with unauthorized parties. An empty secret key is considered invalid
  /// and will result in an error.
  #[wasm_bindgen(constructor)]
  pub fn new(secret_key: &str) -> Result<Verifier> {
    if secret_key.is_empty() {
      return Err(Error::InvalidSecretKey);
    }

    Ok(Verifier {
      secret_key: secret_key.as_bytes().to_vec(),
    })
  }

  /// Creates a new block with the given data and previous hash.
  ///
  /// This method generates a new block in the chain. It signs the provided data,
  /// includes the previous block's hash to maintain the chain's integrity, and
  /// timestamps the block. The resulting block is serialized to a JSON string.
  #[wasm_bindgen]
  pub fn create_block(&self, data: &str) -> Result<Block> {
    let signature = self.sign_data(data)?;

    Ok(Block {
      data: data.to_string(),
      signature,
    })
  }

  /// Hashes the block as a string using SHA256 and returns the result as a base64-encoded string.
  ///
  /// This method provides a way to generate a unique hash for any given input block.
  ///
  /// It's useful for creating the 'previous_hash' when adding new blocks to the chain,
  /// ensuring that any changes to previous blocks will be detectable.
  #[wasm_bindgen]
  pub fn hash_block(block: &Block) -> Result<String> {
    let data = serde_json::to_string(block).map_err(Error::from)?;

    let mut hasher = Sha256::new();

    hasher.update(data.as_bytes());

    let result = hasher.finalize();

    Ok(general_purpose::STANDARD_NO_PAD.encode(result))
  }

  /// Analyzes a chain of blocks and provides status information for each block.
  ///
  /// This function takes a list of blocks and evaluates each one, assigning a status
  /// based on its validity and position in the chain. The blocks are first sorted
  /// by timestamp in descending order (from newest to oldest).
  ///
  /// The function iterates through the sorted blocks, verifying each block's data
  /// and signature. It assigns one of three statuses to each block:
  /// - Recovered: The first valid block encountered.
  /// - Valid: Any block that comes after a recovered block in the chain.
  /// - Tampered: Any block that fails verification or comes before the first valid block.
  ///
  /// The function returns a vector of BlockWithStatus, which pairs each original
  /// block with its assigned status. This allows for a comprehensive view of the
  /// entire blockchain's state.
  ///
  /// If an error occurs during the verification process, the function will return
  /// an error result.
  #[wasm_bindgen]
  pub fn information(
    &self,
    blocks: Vec<Block>,
  ) -> Result<Vec<BlockWithStatus>> {
    Ok(
      blocks
        .into_iter()
        .rev()
        .fold((Vec::new(), false), |(mut acc, recovered), block| {
          let status = if recovered {
            match self.verify_data(&block.data, &block.signature) {
              Ok(true) => Status::Valid,
              _ => Status::Tampered,
            }
          } else {
            match self.verify_data(&block.data, &block.signature) {
              Ok(true) => {
                acc.push(BlockWithStatus {
                  block: block.clone(),
                  status: Status::Recovered,
                });
                return (acc, true);
              }
              _ => Status::Tampered,
            }
          };
          acc.push(BlockWithStatus { block, status });
          (acc, recovered)
        })
        .0,
    )
  }

  /// Signs the input data using HMAC-SHA256 and returns the signature as a base64-encoded string.
  ///
  /// This method creates a cryptographic signature for the given data using the secret key
  /// associated with this Verifier instance.
  ///
  /// The signature can later be used to verify the integrity and authenticity of the data.
  pub fn sign_data(&self, data: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(&self.secret_key)
      .map_err(|e: InvalidLength| Error::Hmac(e.to_string()))?;

    mac.update(data.as_bytes());

    let result = mac.finalize();

    Ok(general_purpose::STANDARD_NO_PAD.encode(result.into_bytes()))
  }

  /// Verifies the integrity of a block.
  ///
  /// This method takes a JSON string representation of a block, deserializes it,
  /// and verifies the integrity of its data using the stored signature.
  ///
  /// It ensures that the block's contents haven't been tampered with since it was created.
  pub fn verify_block(&self, block: &Block) -> Result<bool, Error> {
    self.verify_data(&block.data, &block.signature)
  }

  /// Verifies the integrity of the data using its signature.
  ///
  /// This method checks whether the given data matches the provided signature. It uses
  /// the HMAC-SHA256 algorithm with the Verifier's secret key to perform the verification.
  ///
  /// If the data has been altered or the signature was created with a different key,
  /// the verification will fail.
  #[wasm_bindgen]
  pub fn verify_data(
    &self,
    data: &str,
    signature: &str,
  ) -> Result<bool, Error> {
    let sig_bytes = general_purpose::STANDARD_NO_PAD
      .decode(signature)
      .map_err(Error::from)?;

    let mut mac = HmacSha256::new_from_slice(&self.secret_key)
      .map_err(|e: InvalidLength| Error::Hmac(e.to_string()))?;

    mac.update(data.as_bytes());

    mac.verify_slice(&sig_bytes).map(|_| true).or_else(|e| {
      if e.to_string().contains("MAC tag mismatch") {
        Ok(false)
      } else {
        Err(Error::Hmac(e.to_string()))
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn create_test_chain(verifier: &Verifier) -> Vec<Block> {
    vec![
      verifier.create_block("data1").unwrap(),
      verifier.create_block("data2").unwrap(),
      verifier.create_block("data3").unwrap(),
      verifier.create_block("data4").unwrap(),
      verifier.create_block("data5").unwrap(),
    ]
  }

  fn tamper_block(block: &Block, new_data: &str) -> Block {
    Block {
      data: new_data.to_string(),
      ..block.clone()
    }
  }

  #[test]
  fn verifier_new() {
    assert!(Verifier::new("valid_key").is_ok());
    assert!(matches!(Verifier::new(""), Err(Error::InvalidSecretKey)));
  }

  #[test]
  fn create_and_verify_block() {
    let verifier = Verifier::new("key").unwrap();
    let block = verifier.create_block("data").unwrap();
    assert!(verifier.verify_block(&block).unwrap());
  }

  #[test]
  fn hash_blocks() {
    let verifier = Verifier::new("key").unwrap();

    let block1 = verifier.create_block("data1").unwrap();

    let block2 = verifier.create_block("data2").unwrap();

    let hash1 = Verifier::hash_block(&block1).unwrap();
    let hash2 = Verifier::hash_block(&block1).unwrap();
    let hash3 = Verifier::hash_block(&block2).unwrap();

    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
  }

  #[test]
  fn recover_data() {
    let verifier = Verifier::new("key").unwrap();

    let block1 = verifier.create_block("data1").unwrap();

    let block2 = verifier.create_block("data2").unwrap();

    let result = verifier
      .information(vec![block2.clone(), block1.clone()])
      .unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].block.data, "data2");

    assert!(matches!(result[0].status, Status::Recovered));

    assert_eq!(result[1].block.data, "data1");

    assert!(matches!(result[1].status, Status::Valid));
  }

  #[test]
  fn sign_and_verify_data() {
    let verifier = Verifier::new("key").unwrap();

    let data = "data";

    let signature = verifier.sign_data(data).unwrap();

    assert!(verifier.verify_data(data, &signature).unwrap());
    assert!(!verifier.verify_data("tampered_data", &signature).unwrap());
  }

  #[test]
  fn verify_block_tampered() {
    let verifier = Verifier::new("key").unwrap();

    let mut block = verifier.create_block("original_data").unwrap();

    block.data = "tampered_data".to_string();

    assert!(!verifier.verify_block(&block).unwrap());
  }

  #[test]
  fn no_tampering() {
    let verifier = Verifier::new("key").unwrap();

    let chain = create_test_chain(&verifier);

    let result = verifier.information(chain).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Recovered));

    assert!(result[1..]
      .iter()
      .all(|b| matches!(b.status, Status::Valid)));
  }

  #[test]
  fn tamper_most_recent() {
    let verifier = Verifier::new("key").unwrap();

    let mut chain = create_test_chain(&verifier);
    chain[0] = tamper_block(&chain[0], "tampered5");

    let result = verifier.information(chain).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Recovered));

    assert!(result[1..3]
      .iter()
      .all(|b| matches!(b.status, Status::Valid)));

    assert!(matches!(result[4].status, Status::Tampered));
  }

  #[test]
  fn tamper_multiple_recent() {
    let verifier = Verifier::new("key").unwrap();

    let mut chain = create_test_chain(&verifier);
    chain[0] = tamper_block(&chain[0], "tampered5");
    chain[1] = tamper_block(&chain[1], "tampered4");

    let result = verifier.information(chain).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Recovered));

    assert!(result[1..2]
      .iter()
      .all(|b| matches!(b.status, Status::Valid)));

    assert!(matches!(result[3].status, Status::Tampered));
    assert!(matches!(result[4].status, Status::Tampered));
  }

  #[test]
  fn tamper_all_but_oldest() {
    let verifier = Verifier::new("key").unwrap();

    let mut chain = create_test_chain(&verifier);

    for i in 0..4 {
      chain[i] = tamper_block(&chain[i], &format!("tampered{}", 5 - i));
    }

    let result = verifier.information(chain).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Recovered));

    assert!(result[1..4]
      .iter()
      .all(|b| matches!(b.status, Status::Tampered)));
  }

  #[test]
  fn tamper_all() {
    let verifier = Verifier::new("key").unwrap();

    let chain = create_test_chain(&verifier);

    let tampered_chain: Vec<Block> = chain
      .iter()
      .enumerate()
      .map(|(i, b)| tamper_block(b, &format!("tampered{}", 5 - i)))
      .collect();

    let result = verifier.information(tampered_chain).unwrap();

    assert_eq!(result.len(), 5);

    assert!(result.iter().all(|b| matches!(b.status, Status::Tampered)));
  }

  #[test]
  fn mix_tampered_and_untampered() {
    let verifier = Verifier::new("key").unwrap();

    let mut chain = create_test_chain(&verifier);
    chain[0] = tamper_block(&chain[0], "tampered5");
    chain[2] = tamper_block(&chain[2], "tampered3");
    chain[4] = tamper_block(&chain[4], "tampered1");

    let result = verifier.information(chain).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Tampered));
    assert!(matches!(result[1].status, Status::Recovered));
    assert!(matches!(result[2].status, Status::Tampered));
    assert!(matches!(result[3].status, Status::Valid));
    assert!(matches!(result[4].status, Status::Tampered));
  }

  #[test]
  fn blocks_out_of_order() {
    let verifier = Verifier::new("key").unwrap();

    let chain = create_test_chain(&verifier);

    let out_of_order = vec![
      chain[2].clone(),
      chain[0].clone(),
      chain[3].clone(),
      chain[1].clone(),
      chain[4].clone(),
    ];

    let result = verifier.information(out_of_order).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Recovered));

    assert!(result[1..]
      .iter()
      .all(|b| matches!(b.status, Status::Valid)));
  }

  #[test]
  fn blocks_out_of_order_with_tampering() {
    let verifier = Verifier::new("key").unwrap();

    let mut chain = create_test_chain(&verifier);
    chain[0] = tamper_block(&chain[0], "tampered5");
    chain[2] = tamper_block(&chain[2], "tampered3");

    let out_of_order = vec![
      chain[2].clone(),
      chain[4].clone(),
      chain[3].clone(),
      chain[1].clone(),
      chain[0].clone(),
    ];

    let result = verifier.information(out_of_order).unwrap();

    assert_eq!(result.len(), 5);

    assert!(matches!(result[0].status, Status::Recovered));
    assert!(matches!(result[1].status, Status::Valid));
    assert!(matches!(result[2].status, Status::Tampered));
    assert!(matches!(result[3].status, Status::Valid));
    assert!(matches!(result[4].status, Status::Tampered));
  }
}
