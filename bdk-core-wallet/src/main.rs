use bdk::bitcoin::Network;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::Amount;
use bdk::bitcoincore_rpc::{Auth as rpc_auth, Client, RpcApi};

use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcConfig, wallet_name_from_descriptor};
use bdk::blockchain::{ConfigurableBlockchain, NoopProgress};

use bdk::keys::bip39::{Mnemonic, Language, MnemonicType};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey, DescriptorKey};
use bdk::keys::DescriptorKey::Secret;

use bdk::miniscript::miniscript::Segwitv0;

use bdk::Wallet;
use bdk::wallet::{AddressIndex, signer::SignOptions};

use bdk::sled;

use std::path;
use std::str::FromStr;

fn main() {
   let (receive_desc, change_desc) = get_descriptors();
   println!("recv: {:#?}, \nchng: {:#?}", receive_desc, change_desc);
}

fn get_descriptors() -> (String, String) {
    // secp256k1 context
    let secp = Secp256k1::new();
    
    // create mnemonic and master private key with password unlock
    let password = Some("random password".to_string());
    let mnemonic: GeneratedKey<_, Segwitv0> = Mnemonic::generate((MnemonicType::Words12, Language::English)).unwrap();
    let mnemonic = mnemonic.into_key();
    let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
    let xprv = xkey.into_xprv(Network::Regtest).unwrap();

    // create derived private key with following derviation paths:
    // receive: "m/84h/1h/0h/0"
    // change: "m/84h/1h/0h/1"
    let mut keys = Vec::new();
    
    for path in ["m/84h/1h/0h/0", "m/84h/1h/0h/1"] {
        let deriv_path: DerivationPath = DerivationPath::from_str(path).unwrap();
        let derived_xprv = &xprv.derive_priv(&secp, &deriv_path).unwrap();
        let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);
        let derived_xprv_desc_key: DescriptorKey<Segwitv0> = derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default()).unwrap();

        if let Secret(key, _, _) = derived_xprv_desc_key {
            let mut desc = "wpkh(".to_string();
            desc.push_str(&key.to_string());
            desc.push_str(")");
            keys.push(desc);
        }
    }

    (keys[0].clone(), keys[1].clone())
}