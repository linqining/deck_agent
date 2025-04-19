use ark_ec::AffineCurve;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use starknet_curve::StarkwareParameters;

type PublicKey = GroupAffine<StarkwareParameters>;
type PrivateKey = <ark_ec::short_weierstrass_jacobian::GroupAffine<StarkwareParameters> as AffineCurve>::ScalarField;


pub struct GameUser {
    pub game_user_id:String,
    pub user_id: String,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl GameUser {
    pub fn new(game_user_id:String,user_id:String,public_key: PublicKey,private_key: PrivateKey) -> Self {
        Self{
            game_user_id:game_user_id,
            user_id:user_id,
            public_key:public_key,
            private_key:private_key,
        }
    }
}