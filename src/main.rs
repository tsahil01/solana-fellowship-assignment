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
use std::{mem, str::FromStr};
use spl_token::instruction as token_instruction;
use bs58;
use serde::Serialize;
use base64;

use crate::{res_input::{SendSolRequest, SignRequest}, res_output::{AccountInfo, KeyPairResponse, SendSolResponse, SignResponse, SuccessResponse, TokenCreateResponse}};
use crate::res_input::{CreateTokenRequest, MintTokenRequest};

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

    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let response = TokenCreateResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(instruction.data),
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[handler]
async fn mint_token(req: Json<MintTokenRequest>) -> Result<Json<SuccessResponse<TokenCreateResponse>>> {
    let mint = Pubkey::from_str(&req.mint)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;
    let destination = Pubkey::from_str(&req.destination)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;
    let authority = Pubkey::from_str(&req.authority)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;

    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let response = TokenCreateResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(instruction.data),
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[handler]
async fn sign(req: Json<SignRequest>) -> Result<Json<SuccessResponse<SignResponse>>> {
    let message = &req.message;
    let secret = &req.secret;

    let keypair = Keypair::from_base58_string(&secret);

    let signature = keypair.sign_message(message.as_bytes());

    let response = SignResponse {
        signature: signature.to_string(),
        public_key: keypair.pubkey().to_string(),
        message: message.clone(),
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[handler]
async fn send_sol(req: Json<SendSolRequest>) -> Result<Json<SuccessResponse<SendSolResponse>>> {
    if req.lamports == 0 {
        return Err(poem::Error::from_string(
            "lamports cant be 0",
            poem::http::StatusCode::BAD_REQUEST,
        ));
    }

    let from = Pubkey::from_str(&req.from)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;
    let to = Pubkey::from_str(&req.to)
        .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST))?;

    if from == to {
        return Err(poem::Error::from_string(
            "from and to cant be the same",
            poem::http::StatusCode::BAD_REQUEST,
        ));
    }

    let instruction = solana_sdk::system_instruction::transfer(&from, &to, req.lamports);

    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let response = SendSolResponse {
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
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign))
        .at("/send/sol", post(send_sol));

    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .name("hello-world")
        .run(app)
        .await
}