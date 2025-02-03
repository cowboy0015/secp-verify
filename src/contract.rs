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

    let res = ADOContract::default().execute(ctx, msg)?;

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
) -> Result<bool, ContractError> {
    let address = derive_address(&derive_prefix(ctx.env), public_key).unwrap();
    ensure!(address == signer_addr, ContractError::InvalidAddress {  });

    let message_hash: [u8; 32] = Sha256::new().chain(&msg).finalize().into();

    match ctx
        .deps
        .api
        .secp256k1_verify(&message_hash, signature, public_key)
    {
        Ok(valid) => Ok(valid),
        Err(_) => Ok(false),
    }
}

pub fn derive_prefix(env: Env) -> String {
    let contract_address = env.contract.address.into_string();
    if contract_address.len() > 39 {
        contract_address.chars().take(contract_address.len() - 39).collect()
    } else {
        "cosmos".to_string()
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
    use super::{derive_address, verify_signature};
    use andromeda_std::common::context::ExecuteContext;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use sha2::{digest::Update, Digest, Sha256};

    #[test]
    fn test_verify_signature() {
        let msg: String = "Hello World!".to_string();

        // Signing
        let message_digest = Sha256::new().chain(msg.clone());

        let secret_key = SigningKey::random(&mut OsRng);
        let signature = secret_key
            .sign_digest_recoverable(message_digest)
            .unwrap()
            .0;

        let public_key = secret_key.verifying_key();
        let binding = public_key.to_encoded_point(false);
        let public_key_bytes = binding.as_bytes();

        // verifying
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("owner", &[]);
        let address = derive_address("cosmos", public_key_bytes).unwrap();

        let ctx = ExecuteContext::new(deps.as_mut(), info, env);
        assert!(verify_signature(ctx, msg, &signature.to_bytes(), public_key_bytes, address).unwrap());
    }
}