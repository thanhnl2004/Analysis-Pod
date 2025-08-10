import 'package:encrypt/encrypt.dart';

void main(List<String> arguments) {
  if (arguments.length != 2) {
    print("[ERR] must provide two arguments: \"ivVal (base64 encoded string)\", \"encrypted_value (string)\"");
  } else {
    String encKey = "YOUR_SECURITY_KEY";
    String ivVal  = arguments[0];
    String encVal = arguments[1];
    String decryptedText = decryptVal(encKey, encVal, ivVal);

    print(decryptedText);
  }
}

// Decrypt a ciphertext value
// Extracted from https://github.com/anusii/solid-encrypt/blob/main/lib/enc_client.dart

String decryptVal(String encKey, String encVal, String ivVal) {
  final key = Key.fromUtf8(encKey);
  final iv = IV.fromBase64(ivVal);
  final encrypter = Encrypter(AES(key));
  final ecc = Encrypted.from64(encVal);
  final plaintextVal = encrypter.decrypt(ecc, iv: iv);

  return plaintextVal;
}
