use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub mintAuthority: String, 
    pub mint: String,
    pub decimals: u8,
}
