#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError};
use andromeda_std::{
    ado_base::InstantiateMsg as BaseInstantiateMsg, ado_contract::ADOContract, common::{actions::call_action, context::ExecuteContext}, error::ContractError
};
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
        .add_attribute("owner", info.sender)
        )
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, ContractError> {
    let ctx = ExecuteContext::new(deps, info, env);
    if let ExecuteMsg::AMPReceive(pkt) = msg {
        ADOContract::default().execute_amp_receive(
            ctx,
            pkt,
            handle_execute,
        )
    } else {
        handle_execute(ctx, msg)
    }
}

pub fn handle_execute(
    mut ctx: ExecuteContext,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
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

pub fn verify_signature(ctx: ExecuteContext, msg: String, signature: &[u8],public_key: &[u8]) -> Result<bool, ContractError> {
// pub fn verify_signature(msg: String, signature: &[u8],public_key: &[u8], signer_addr: Addr) -> Result<bool, ContractError> {
    let message_digest = Sha256::new().chain(&msg);
    let message_hash = message_digest.clone().finalize();
    let message_hash: [u8; 32] = message_hash.try_into().map_err(|_| ContractError::Std(StdError::generic_err(
        format!("Generating Hash For \"{:?}\" failed", &msg)
    )))?;

    match ctx.deps.api.secp256k1_verify(&message_hash, signature, public_key) {
        Ok(res) => Ok(res),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    // use ed25519_zebra::{SigningKey, VerificationKey};
    use andromeda_std::common::context::ExecuteContext;
    use bech32::{ToBase32, Variant};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use sha2::{digest::Update, Digest, Sha256};

    use crate::contract::verify_signature;
    // #[test]
    // fn test_ed25519() {
    //     let secret_key_bytes: [u8; 32] = [223, 51, 204, 10, 98, 158, 64, 30, 96, 55, 122, 180, 0, 56, 59, 58, 78, 66, 170, 41, 163, 197, 79, 210, 205, 40, 50, 173, 66, 167, 199, 185];
    //     let secret_key = SigningKey::from(secret_key_bytes);

    //     let public_key = VerificationKey::from(&secret_key);
    //     let public_key_bytes: [u8; 32] = public_key.into();
    //     println!("pub_key: {:?}", public_key_bytes);

    //     // verifying
    //     let hash = Sha256::digest(public_key_bytes);
    //     let truncated_address = &hash[..20];

    //     let bech32_address = bech32::encode("cosmos", truncated_address.to_base32(), Variant::Bech32)
    //     .expect("Bech32 encoding failed");

    //     let expected_addr = "cosmos1428shsddyrk3lrl7vf4hsr9uhzz6prcdlxrrdd".to_string();
    //     assert_eq!(bech32_address, expected_addr); 
    // }
    #[test]
    fn test_verify_signature() {
        let msg: String = "Hello World!".to_string();

        // Signing
        let message_digest = Sha256::new().chain(msg.clone());

        let secret_key_bytes: [u8; 32] = [223, 51, 204, 10, 98, 158, 64, 30, 96, 55, 122, 180, 0, 56, 59, 58, 78, 66, 170, 41, 163, 197, 79, 210, 205, 40, 50, 173, 66, 167, 199, 185];
        let secret_key = k256::ecdsa::SigningKey::from_slice(&secret_key_bytes).unwrap();
        // let secret_key = SigningKey::random(&mut OsRng);
        let signature = secret_key.sign_digest_recoverable(message_digest).unwrap().0;

        let public_key = secret_key.verifying_key();
        let binding = public_key.to_encoded_point(false);
        let public_key_bytes = binding.as_bytes();

        // verifying
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("owner", &[]);

        let ctx = ExecuteContext::new(deps.as_mut(), info, env);
        assert!(verify_signature(ctx, msg, &signature.to_bytes(), public_key_bytes).unwrap());

        // generating address
        let hash = Sha256::digest(public_key_bytes);
        let truncated_address = &hash[..20];

        let bech32_address = bech32::encode("cosmos", truncated_address.to_base32(), Variant::Bech32)
        .expect("Bech32 encoding failed");

        let expected_addr = "cosmos1428shsddyrk3lrl7vf4hsr9uhzz6prcdlxrrdd".to_string();
        assert_eq!(bech32_address, expected_addr); 
    }
}
