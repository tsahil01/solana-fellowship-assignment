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
    let mint_authority = validate_address(&req.mintAuthority, "mint authority")?;
    let mint = validate_address(&req.mint, "mint")?;
    
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
    if req.amount == 0 {
        return Err(error_response("Invalid amount"));
    }

    let mint = validate_address(&req.mint, "mint")?;
    let destination = validate_address(&req.destination, "destination")?;
    let authority = validate_address(&req.authority, "authority")?;

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
        .map_err(|_| error_response("Invalid secret key"))?;

    let keypair = Keypair::from_bytes(&secret_bytes)
        .map_err(|_| error_response("Invalid secret key"))?;

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

    let pubkey = validate_address(&req.pubkey, "public key")?;
    
    let signature_bytes = base64::decode(&req.signature)
        .map_err(|_| error_response("Invalid signature format"))?;
    
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| error_response("Invalid signature"))?;

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
    if req.lamports == 0 {
        return Err(error_response("Invalid amount"));
    }

    let from = validate_address(&req.from, "from")?;
    let to = validate_address(&req.to, "to")?;

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

fn validate_address(address: &str, field_name: &str) -> Result<Pubkey, poem::Error> {
    if address.is_empty() {
        return Err(error_response("Missing required fields"));
    }
    
    match Pubkey::from_str(address) {
        Ok(pubkey) => {
            Ok(pubkey)
        }
        Err(_) => {
            Err(error_response(&format!("Invalid {} address", field_name)))
        }
    }
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
    if req.amount == 0 {
        return Err(error_response("Invalid amount"));
    }

    let destination = validate_address(&req.destination, "destination")?;
    let mint = validate_address(&req.mint, "mint")?;
    let owner = validate_address(&req.owner, "owner")?;

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