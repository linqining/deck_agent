use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeAggregateKeyRequest{
    pub joined_key: String, // if accept other player's proof, return the joined key of all player
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeAggregateKeyResponse{
    pub joined_key: String, // if accept other player's proof, return the joined key of all player
    pub is_accept:bool, //
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUpDeckRequest{
    pub user_id: String, // user_id provide by the agent service
    pub game_id: String,
    pub game_user_id: String, // user identity among this round
    pub rng_seed: u64,
    // pub m:usize,
    // pub n:usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUpDeckResponse{
    pub user_id:String,
    pub game_id:String,
    pub game_user_id:String,
    pub user_public_key:Vec<u8>,
    pub user_key_proof:Vec<u8>,
}



