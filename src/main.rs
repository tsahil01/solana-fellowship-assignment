use poem::{
    get, handler, listener::TcpListener, post, Route, Server,
    web::Json, Response, Result, Request, http::StatusCode,
};
use solana_sdk::{
    signature::{Keypair, Signature},
    signer::Signer,
    pubkey::Pubkey,
    instruction::{Instruction, AccountMeta},
};
use std::{mem, str::FromStr};
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use bs58;
use serde::Serialize;
use base64;
use serde_json;

use crate::{
    res_input::{SendSolRequest, SignRequest, VerifyRequest, CreateTokenRequest, MintTokenRequest, SendTokenRequest}, 
    res_output::{AccountInfo, KeyPairResponse, SendSolResponse, SignResponse, SuccessResponse, TokenCreateResponse, VerifyResponse, ErrorResponse, SendTokenResponse, SendTokenAccountInfo}
};

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
    if req.mintAuthority.is_empty() {
        return Err(error_response("Mint authority empty"));
    }
    if req.mint.is_empty() {
        return Err(error_response("Mint empty"));
    }

    let mint_authority = Pubkey::from_str(&req.mintAuthority)
        .map_err(|e| error_response(&e.to_string()))?;
    let mint = Pubkey::from_str(&req.mint)
        .map_err(|e| error_response(&e.to_string()))?;
    
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ).map_err(|e| error_response(&e.to_string()))?;

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
    
    if req.mint.is_empty() {
        return Err(error_response("Mint empty"));
    }
    if req.destination.is_empty() {
        return Err(error_response("Destination empty"));
    }
    if req.authority.is_empty() {
        return Err(error_response("Authority empty"));
    }
    if req.amount == 0 {
        return Err(error_response("Amount 0"));
    }

    let mint = Pubkey::from_str(&req.mint)
        .map_err(|e| error_response(&e.to_string()))?;
    let destination = Pubkey::from_str(&req.destination)
        .map_err(|e| error_response(&e.to_string()))?;
    let authority = Pubkey::from_str(&req.authority)
        .map_err(|e| error_response(&e.to_string()))?;

    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).map_err(|e| error_response(&e.to_string()))?;

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

    
    if message.is_empty() {
        return Err(error_response("Message empty"));
    }
    if secret.is_empty() {
        return Err(error_response("Secret empty"));
    }

    let secret_bytes = bs58::decode(secret)
        .into_vec()
        .map_err(|e| error_response(&format!("Invalid base58 string: {}", e)))?;

    let keypair = Keypair::from_bytes(&secret_bytes)
        .map_err(|e| error_response(&format!("Invalid secret key: {}", e)))?;

    let signature = keypair.sign_message(message.as_bytes());

    let response = SignResponse {
        signature: base64::encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: message.clone(),
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[handler]
async fn verify(req: Json<VerifyRequest>) -> Result<Json<SuccessResponse<VerifyResponse>>> {
    
    if req.message.is_empty() {
        return Err(error_response("Message empty"));
    }
    if req.signature.is_empty() {
        return Err(error_response("Signature empty"));
    }
    if req.pubkey.is_empty() {
        return Err(error_response("Public key empty"));
    }

    let pubkey = Pubkey::from_str(&req.pubkey)
        .map_err(|e| error_response(&e.to_string()))?;
    
    let signature_bytes = base64::decode(&req.signature)
        .map_err(|e| error_response(&format!("Invalid base64: {}", e)))?;
    
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| error_response(&format!("Invalid sign format: {}", e)))?;

    let valid = signature.verify(&pubkey.as_ref(), req.message.as_bytes());

    let response = VerifyResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    Ok(Json(SuccessResponse::new(response)))
}

#[handler]
async fn send_sol(req: Json<SendSolRequest>) -> Result<Json<SuccessResponse<SendSolResponse>>> {
    
    if req.from.is_empty() {
        return Err(error_response("From address empty"));
    }
    if req.to.is_empty() {
        return Err(error_response("To address empty"));
    }
    if req.lamports == 0 {
        return Err(error_response("Lamports 0"));
    }

    let from = Pubkey::from_str(&req.from)
        .map_err(|e| error_response(&e.to_string()))?;
    let to = Pubkey::from_str(&req.to)
        .map_err(|e| error_response(&e.to_string()))?;

    if from == to {
        return Err(error_response("From and to same"));
    }

    let instruction = solana_sdk::system_instruction::transfer(&from, &to, req.lamports);

    let accounts: Vec<String> = instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect();

    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(instruction.data),
    };

    Ok(Json(SuccessResponse::new(response)))
}

fn error_response(message: &str) -> poem::Error {
    let error_response = ErrorResponse::new(message.to_string());
    poem::Error::from_response(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .content_type("application/json")
        .body(serde_json::to_string(&error_response).unwrap()))
}

#[handler]
async fn send_token(req: Json<SendTokenRequest>) -> Result<Json<SuccessResponse<SendTokenResponse>>> {
    
    if req.destination.is_empty() {
        return Err(error_response("Destination empty"));
    }
    if req.mint.is_empty() {
        return Err(error_response("Mint empty"));
    }
    if req.owner.is_empty() {
        return Err(error_response("Owner empty"));
    }
    if req.amount == 0 {
        return Err(error_response("Amount 0"));
    }

    let destination = Pubkey::from_str(&req.destination).map_err(|e| error_response(&e.to_string()))?;
    let mint = Pubkey::from_str(&req.mint).map_err(|e| error_response(&e.to_string()))?;
    let owner = Pubkey::from_str(&req.owner).map_err(|e| error_response(&e.to_string()))?;

    let source = get_associated_token_address(&owner, &mint);

    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,
        &[],
        req.amount,
    ).map_err(|e| error_response(&e.to_string()))?;

    let accounts: Vec<SendTokenAccountInfo> = instruction.accounts.iter().map(|acc| SendTokenAccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let response = SendTokenResponse {
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
        .at("/message/verify", post(verify))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token));

    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .name("hello-world")
        .run(app)
        .await
}