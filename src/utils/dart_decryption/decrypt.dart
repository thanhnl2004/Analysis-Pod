import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:dotenv/dotenv.dart';

void main(List<String> arguments) {
  var env = DotEnv(includePlatformEnvironment: true)
    ..load(['.env']);

  String ivSessionKey = "On8cmqkhyZl6FcMuGDvYDw==";
  String sessionKey = "K4tMlGni0PhTmv4Ew7NmF993KQP586phRPnJPy16lOfsLASZi0ecp9MPm+39+6rD"; 
  String securityKey  = env['SECURITY_KEY'] ?? '';
  String ivVal  = "n783AWllgyU7nC3ojnt0nw==";
  String encVal = "GmwGTQBN6tJ9ugBwHJ/dExvI1JCO/uFwjv9LYgZJjUGEN/R+Ra0DVc7VOYq2LKaTxOueQ1lnXDiOT+NIeEeYOeRB71KIhifAxavENx3ha/tmUnoSUOEU2C0f5905WtCkZPfu4Q5OnJ8dBaqBzdyF+bWCEA/KM1ADZz+QnCz2uGc=";

  Key masterKey = genMasterKey(securityKey);
  print("Master Key: " + masterKey.base64);

  String decryptedSessionedKey = decryptData(sessionKey, masterKey, IV.fromBase64(ivSessionKey));
  print("Decrypted Sessioned Key: " + decryptedSessionedKey);

  String decryptedData = decryptData(encVal, Key.fromBase64(decryptedSessionedKey), IV.fromBase64(ivVal));
  print("Decrypted Data: " + decryptedData);

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
