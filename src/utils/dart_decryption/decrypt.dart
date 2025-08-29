import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:dotenv/dotenv.dart';
import 'dart:io';


void main(List<String> arguments) {
  var env = DotEnv(includePlatformEnvironment: true)
    ..load(['.env']);

  Map<String, Map<String, String>> keysData = parseIndKeysFile('../ind-keys.ttl');
  Map<String, String> bloodPressureData = parseBloodPressureFile('../blood_pressure_2025-08-19T03-46-01.json.enc.ttl');
  String targetPath = bloodPressureData['path']!;
  String ivVal = bloodPressureData['iv']!;
  String encVal = bloodPressureData['encData']!;

  String? matchingKey;
  for (String key in keysData.keys) {
    if (keysData[key]!['path'] == targetPath) {
      matchingKey = key;
      break;
    }
  }

  if (matchingKey == null) {
    print("No matching key found for path: $targetPath");
    return;
  }

  String sessionKey = keysData[matchingKey]!['sessionKey']!;
  String ivSessionKey = keysData[matchingKey]!['iv']!;

  Key masterKey = genMasterKey(env['SECURITY_KEY'] ?? '');
  String decryptedSessionedKey = decryptData(sessionKey, masterKey, IV.fromBase64(ivSessionKey));
  String decryptedData = decryptData(encVal, Key.fromBase64(decryptedSessionedKey), IV.fromBase64(ivVal));

  Map<String, dynamic> decryptedDataMap = jsonDecode(decryptedData);
  print("Timestamp: " + decryptedDataMap['timestamp']);
  
  print("Responses: " + decryptedDataMap['responses'].toString());

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

Map<String, Map<String, String>> parseIndKeysFile(String filename) {
  File file = File(filename);
  String content = file.readAsStringSync();
  Map<String, Map<String, String>> data = {};

  List<String> lines = content.split('\n');
  String? currentSubject;

  for (String line in lines) {
    line = line.trim();
    if (line.isEmpty || line.startsWith('@prefix')) continue;

    if (line.startsWith('<') && line.contains('>') && line.contains('solidTerms:path')) {
      RegExp subjectRegex = RegExp(r'<([^>]+)>');
      RegExp pathRegex = RegExp(r'solidTerms:path "([^"]+)"');

      Match? subjectMatch = subjectRegex.firstMatch(line);
      Match? pathMatch = pathRegex.firstMatch(line);

      if (subjectMatch != null && pathMatch != null) {
        currentSubject = subjectMatch.group(1)!;
        data[currentSubject] = {'path':pathMatch.group(1)!};
      } 
    } else if (currentSubject != null && line.contains('solidTerms:iv')) {
      RegExp ivRegex = RegExp(r'solidTerms:iv "([^"]+)"');
      Match? ivMatch = ivRegex.firstMatch(line);

      if (ivMatch != null) {
        data[currentSubject]!['iv'] = ivMatch.group(1)!;
      }
    } else if (currentSubject != null && line.contains('solidTerms:sessionKey')) {
      RegExp sessionKeyRegex = RegExp(r'solidTerms:sessionKey "([^"]+)"');
      Match? sessionKeyMatch = sessionKeyRegex.firstMatch(line);
      if (sessionKeyMatch != null) {
        data[currentSubject]!['sessionKey'] = sessionKeyMatch.group(1)!;
      }
    }
  }

  return data;
}

Map<String, String> parseBloodPressureFile(String filename) {
  File file = File(filename);
  String content = file.readAsStringSync();
  Map<String, String> data = {};

  RegExp pathRegex = RegExp(r'solidTerms:path "([^"]+)"');
  RegExp ivRegex = RegExp(r'solidTerms:iv "([^"]+)"');
  RegExp encDataRegex = RegExp(r'solidTerms:encData "([^"]+)"');

    
  Match? pathMatch = pathRegex.firstMatch(content);
  Match? ivMatch = ivRegex.firstMatch(content);
  Match? encDataMatch = encDataRegex.firstMatch(content);

  if (pathMatch != null) data['path'] = pathMatch.group(1)!;
  if (ivMatch != null) data['iv'] = ivMatch.group(1)!;
  if (encDataMatch != null) data['encData'] = encDataMatch.group(1)!;
  
  return data;
  

}