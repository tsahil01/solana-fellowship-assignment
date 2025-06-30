use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub mintAuthority: String, 
    pub mint: String,
    pub decimals: u8,
}

#[derive(Serialize, Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}