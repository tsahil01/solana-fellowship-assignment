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


#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String,
    pub secret: String,
}


#[derive(Debug, Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}