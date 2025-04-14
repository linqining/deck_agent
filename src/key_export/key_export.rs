// use ark_ec::{ ProjectiveCurve};
// use ark_serialize::{CanonicalSerialize};
// use asn1_der::{DerNode, DerTag};
// use base64::Engine;
//
// // 示例曲线：secp256k1
// type C = ark_secp256k1::Projective;
//
// fn main() {
//     // 1. 生成公私钥对
//     let (private_key, public_key) = generate_keypair::<C>();
//
//     // 2. 序列化公钥为 SEC1 压缩格式
//     let public_key_bytes = serialize_public_key(&public_key);
//
//     // 3. 构建 ASN.1 DER 结构
//     let der_bytes = build_der_structure::<C>(&public_key_bytes);
//
//     // 4. 转换为 PEM 格式
//     let pem = encode_pem(&der_bytes);
//
//     println!("PEM Public Key:\n{}", pem);
// }
//
// use ark_std::{rand::Rng, UniformRand};
//
// // 假设 C 是具体的曲线类型（如 ark_secp256k1::Projective）
// fn generate_keypair<C: ProjectiveCurve>() -> (C::ScalarField, C) {
//     let mut rng = ark_std::rand::thread_rng();
//     let private_key = C::ScalarField::rand(&mut rng);
//     let public_key = C::generator().mul(&private_key);
//     (private_key, public_key)
// }
//
// fn serialize_public_key<C: ProjectiveCurve>(public_key: &C) -> Vec<u8> {
//     let affine = public_key.into_affine();
//     let mut bytes = Vec::new();
//     affine.serialize_with_mode(&mut bytes, Compress::Yes).unwrap();
//     bytes
// }
//
//
//
// fn build_der_structure<C: ProjectiveCurve>(public_key_bytes: &[u8]) -> Vec<u8> {
//     asn1_der::DerObject::
//     // 算法标识符：ecPublicKey + 曲线 OID
//     let algorithm_identifier = DerNode::from_constructed(
//         DerTag::sequence,
//         vec![
//             DerNode::from_obj(DerTag::oid, "1.2.840.10045.2.1"), // ecPublicKey OID
//             DerNode::from_obj(DerTag::oid, C::OID), // 曲线 OID（如 secp256k1::OID）
//         ],
//     );
//
//     // 公钥位字符串
//     let subject_public_key = DerNode::from_obj(DerTag::bit_string, public_key_bytes);
//
//     // 组合为 SubjectPublicKeyInfo
//     let spki = DerNode::from_constructed(
//         DerTag::sequence,
//         vec![algorithm_identifier, subject_public_key],
//     );
//
//     spki.to_bytes()
// }
//
//
// fn encode_pem(der_bytes: &[u8]) -> String {
//     let base64 = base64::engine::general_purpose::STANDARD.encode(der_bytes);
//     format!(
//         "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
//         wrap_base64(&base64, 64)
//     )
// }
//
// // Base64 换行格式化（每 64 字符换行）
// fn wrap_base64(input: &str, line_len: usize) -> String {
//     input.chars()
//         .collect::<Vec<_>>()
//         .chunks(line_len)
//         .map(|chunk| chunk.iter().collect::<String>())
//         .collect::<Vec<_>>()
//         .join("\n")
// }