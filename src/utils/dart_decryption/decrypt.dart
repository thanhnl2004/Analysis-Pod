import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';

void main(List<String> arguments) {
  // 2025-08-20T08-00-00.json.enc.ttl
  String ivSessionKey = "IYdp7PhLtZwuPV35nMph8Q==";
  String sessionKey = "THkA2JGf1+kjnNLrN01GpEXsq4g2a87SgYG1GI4Dev5H43Wze9o+jtu2wQ28N7z+";
  String securityKey = "thanh505";
  String ivVal  = "MM3Q8NDMVOUgik92fSKUkg==";
  String encVal = "MODMNcpRB9n5B6B1tFCdXjcOCpiXMOywMyqjLu83jvnfJZ9+Dp237HYjCSFjQzMALVs+yZHNtVLoIakepWOCGB/h2na8GhzNcvK20eXQZXY+TdeUTrQXOQAMpdnwCzvBVfrfzMVue6GaRF1dIlOL0AvRj8tYmj3YGNnxZE5P2+E=";

  Key masterKey = genMasterKey(securityKey);
  print(masterKey.base64);

  String decryptedSessionedKey = decryptData(sessionKey, masterKey, IV.fromBase64(ivSessionKey));

  String decryptedData = decryptData(encVal, masterKey, IV.fromBase64(ivVal));

  print(decryptedData);


}

// Decrypt a ciphertext value
// Extracted from https://github.com/anusii/solid-encrypt/blob/main/lib/enc_client.dart
Key genMasterKey(String securityKey) => Key.fromUtf8(
  sha256.convert(utf8.encode(securityKey)).toString().substring(0, 32),
);

String decryptData(
  String encData,
  Key key,
  IV iv, {
  AESMode mode = AESMode.sic,
}) =>
  Encrypter(AES(key, mode: mode)).decrypt(Encrypted.from64(encData), iv: iv);

String decryptVal(String encKey, String encVal, String ivVal) {
  final key = Key.fromUtf8(encKey);
  final iv = IV.fromBase64(ivVal);
  final encrypter = Encrypter(AES(key));
  final ecc = Encrypted.from64(encVal);
  final plaintextVal = encrypter.decrypt(ecc, iv: iv);

  return plaintextVal;
}
