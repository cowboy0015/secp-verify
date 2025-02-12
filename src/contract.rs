use andromeda_std::{
    ado_base::InstantiateMsg as BaseInstantiateMsg,
    ado_contract::ADOContract,
    common::{actions::call_action, context::ExecuteContext},
    error::ContractError,
};
use bech32::{ToBase32, Variant};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{ensure, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{digest::Update, Digest, Sha256};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:secp-verify";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let contract = ADOContract::default();

    let resp = contract.instantiate(
        deps.storage,
        env,
        deps.api,
        &deps.querier,
        info.clone(),
        BaseInstantiateMsg {
            ado_type: CONTRACT_NAME.to_string(),
            ado_version: CONTRACT_VERSION.to_string(),
            kernel_address: msg.kernel_address,
            owner: msg.owner,
        },
    )?;

    Ok(resp
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    
    let ctx = ExecuteContext::new(deps, info, env);
    if let ExecuteMsg::AMPReceive(pkt) = msg {
        ADOContract::default().execute_amp_receive(ctx, pkt, handle_execute)
    } else {
        handle_execute(ctx, msg)
    }
}

pub fn handle_execute(mut ctx: ExecuteContext, msg: ExecuteMsg) -> Result<Response, ContractError> {
    let action_response = call_action(
        &mut ctx.deps,
        &ctx.info,
        &ctx.env,
        &ctx.amp_ctx,
        msg.as_ref(),
    )?;

    let res = match msg {
        ExecuteMsg::VerifySignature {
            msg,
            signature,
            public_key,
            signer_addr ,
            address_prefix,
        } => verify_signature(ctx, msg, &signature, &public_key, signer_addr, address_prefix),
        _ => ADOContract::default().execute(ctx, msg)
    }?;

    Ok(res
        .add_submessages(action_response.messages)
        .add_attributes(action_response.attributes)
        .add_events(action_response.events))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    ADOContract::default().query(deps, env, msg)
}

pub fn verify_signature(
    ctx: ExecuteContext,
    msg: String,
    signature: &[u8],
    public_key: &[u8],
    signer_addr: String,
    address_prefix: String,
) -> Result<Response, ContractError> {
    let address = derive_address(&address_prefix, public_key).unwrap();
    ensure!(address == signer_addr, ContractError::InvalidAddress {  });

    let message_hash: [u8; 32] = Sha256::new().chain(&msg).finalize().into();

    let valid = match ctx
        .deps
        .api
        .secp256k1_verify(&message_hash, signature, public_key)
    {
        Ok(valid) => valid,
        Err(_) => false,
    };
    Ok(
        Response::new()
            .add_attribute("action", "verify_signature")
            .add_attribute("sender", ctx.info.sender)
            .add_attribute("signer_address", signer_addr)
            .add_attribute("msg", msg)
            .add_attribute("is_valid_signature", valid.to_string())
    )
}

pub fn verify_signature_ed25519_verify(
    ctx: ExecuteContext,
    msg: String,
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let message_hash: [u8; 32] = Sha256::new().chain(&msg).finalize().into();

    match ctx
        .deps
        .api
        .secp256k1_verify(&message_hash, signature, public_key)
    {
        Ok(valid) => valid,
        Err(_) => false,
    }
}


pub fn derive_address(prefix: &str, public_key_bytes: &[u8]) -> Result<String, ContractError> {
    let pub_key_compressed = &PublicKey::from_slice(public_key_bytes).unwrap().serialize();

    // Hash with SHA-256
    let sha256_hash = Sha256::digest(pub_key_compressed);

    // Hash with RIPEMD-160
    let ripemd160_hash = Ripemd160::digest(sha256_hash);

    // Encode with bech32
    bech32::encode(prefix, ripemd160_hash.to_base32(), Variant::Bech32).map_err(|_| ContractError::InvalidAddress {  })
}

#[cfg(test)]
mod tests {
    use crate::contract::verify_signature_ed25519_verify;

    use super::{derive_address, verify_signature};
    use andromeda_std::common::context::ExecuteContext;
    use base64::{engine::general_purpose, Engine};
    use cosmwasm_std::{testing::{mock_dependencies, mock_env, mock_info}, Response};
    use k256::{ecdsa::SigningKey};
    use sha2::{digest::Update, Digest, Sha256};

    // #[test]
    // fn test_verify_signature() {
    //     let msg: String = "This is a test message".to_string();

    //     // Signing
    //     let message_digest = Sha256::new().chain(msg.clone());

    //     let secret_key_bytes: Vec<u8> = [84, 35, 175, 254, 171, 196, 230, 87, 129, 42, 71, 87, 143, 137, 78, 55, 198, 161, 14, 188, 104, 236, 224, 130, 146, 199, 93, 64, 35, 67, 10, 192].to_vec();
    //     let secret_key = SigningKey::from_slice(&secret_key_bytes).unwrap();
    //     // let secret_key = SigningKey::random(&mut OsRng);
    //     let signature = secret_key
    //         .sign_digest_recoverable(message_digest)
    //         .unwrap()
    //         .0;

    //     let public_key = secret_key.verifying_key();
    //     let binding = public_key.to_encoded_point(false);
    //     let public_key_bytes = binding.as_bytes();

    //     // verifying
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     let info = mock_info("owner", &[]);
    //     let address = derive_address("andr", public_key_bytes).unwrap();

    //     let ctx = ExecuteContext::new(deps.as_mut(), info, env);
    //     let res = verify_signature(ctx, msg.clone(), &signature.to_bytes(), public_key_bytes, address.clone(), "andr".to_string()).unwrap();
    //     let expected_res = Response::new()
    //         .add_attribute("action", "verify_signature")
    //         .add_attribute("sender", "owner")
    //         .add_attribute("signer_address", address)
    //         .add_attribute("msg", msg)
    //         .add_attribute("is_valid_signature", true.to_string());

    //     assert_eq!(
    //         res, expected_res
    //     )
    // }

    #[test]
    fn test_external_signature() {
        let pubkey_str = "A/Ce/RwG0A+tMNMVgbU/ZBl4I+mIP+eTREJnevJBhrX7";
        let public_key_bytes = general_purpose::STANDARD.decode(pubkey_str).unwrap();

        let signature_str = "6HK+VZUL0+jlQsFsfX0qn1nu32FG23Y1T9g93PBkhFkSB1emZWHV68pbBd/vaik6BbObMjj6BU2qC4uR3DncZw==";
        let signature_bytes = general_purpose::STANDARD.decode(signature_str).unwrap();

        let msg = "eyJhY2NvdW50X251bWJlciI6IjAiLCJjaGFpbl9pZCI6ImFuZHJvbWVkYS0xIiwiZmVlIjp7ImFtb3VudCI6W10sImdhcyI6IjAifSwibWVtbyI6IiIsIm1zZ3MiOlt7InR5cGUiOiJzaWduL01zZ1NpZ25EYXRhIiwidmFsdWUiOnsiZGF0YSI6IlNHVnNiRzhnZDI5eWJHUT0iLCJzaWduZXIiOiJhbmRyMXFrbDdobTNwZHF6ZnllN2d6a3ozbHU3bmtqcnhmemZuNWY2YTQ5In19XSwic2VxdWVuY2UiOiIwIn0=".to_string();
        // let msg = "{\"account_number\":\"0\",\"chain_id\":\"andromeda-1\",\"fee\":{\"amount\":[],\"gas\":\"0\"},\"memo\":\"\",\"msgs\":[{\"type\":\"sign/MsgSignData\",\"value\":{\"data\":\"Hello world\",\"signer\":\"andr1qkl7hm3pdqzfye7gzkz3lu7nkjrxfzfn5f6a49\"}}],\"sequence\":\"0\"}".to_string();
        // let msg_bytes = general_purpose::STANDARD.decode(msg_str).unwrap();
        // let msg = String::from_slice(&msg_bytes).unwrap();

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("owner", &[]);
        let address = derive_address("andr", &public_key_bytes).unwrap();
        println!("address: {:?}", address);
        let ctx = ExecuteContext::new(deps.as_mut(), info, env);
        // println!("verify result: {:?}", verify_signature_ed25519_verify(ctx, msg, &signature_bytes, &public_key_bytes));

        assert!(verify_signature_ed25519_verify(ctx, msg, &signature_bytes, &public_key_bytes));
    }
}