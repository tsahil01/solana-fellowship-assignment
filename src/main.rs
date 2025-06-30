use poem::{
    get, handler, listener::TcpListener, post, web::Path, Route, Server,
    web::Json, Response, Result, Request
};
use solana_sdk::{
    signature::Keypair,
    signer::Signer,
    pubkey::Pubkey,
    instruction::{Instruction, AccountMeta},
};
use std::str::FromStr;
use spl_token::instruction as token_instruction;
use bs58;
use serde::Serialize;
use base64;

use crate::res_output::{SuccessResponse, KeyPairResponse, TokenCreateResponse, AccountInfo};
use crate::res_input::CreateTokenRequest;

mod res_output;
mod res_input;


#[handler]
fn handle_keypair() -> Result<Json<SuccessResponse<KeyPairResponse>>> {
    let key_pair = Keypair::new();
    let pub_key = key_pair.pubkey().to_string();
    let secret_key = bs58::encode(key_pair.to_bytes()).into_string();
    let data = KeyPairResponse {
        pubkey: pub_key,
        secret: secret_key,
    };
    let res = SuccessResponse::new(data);
    Ok(Json(res))
}

#[handler]
async fn create_token(req: Json<CreateTokenRequest>) -> Result<Json<SuccessResponse<TokenCreateResponse>>> {
    let mint_authority = Pubkey::from_str(&req.mintAuthority)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;
    let mint = Pubkey::from_str(&req.mint)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;
    
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ).map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

    // Convert accounts to response format
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    // Create response
    let response = TokenCreateResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(instruction.data),
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {

    let app = Route::new()
    .at("/keypair", post(handle_keypair))
    .at("/create/token", post(create_token));



    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .name("hello-world")
        .run(app)
        .await
}