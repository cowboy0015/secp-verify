use cosmwasm_schema::{cw_serde, QueryResponses};
use andromeda_std::{andr_exec, andr_instantiate, andr_query};

#[andr_instantiate]
#[cw_serde]
pub struct InstantiateMsg {}

#[andr_exec]
#[cw_serde]
pub enum ExecuteMsg {
    VerifySignature {
        msg: String,
        signature: Vec<u8>,
        public_key: Vec<u8>,
        signer_addr: String,

    }
}

#[andr_query]
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
