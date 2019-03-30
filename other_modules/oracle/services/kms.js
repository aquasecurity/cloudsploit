var decryptedData = require( './kms/decryptedData.js' );
var encryptedData = require( './kms/encryptedData.js' );
var generatedKey = require( './kms/generatedKey.js' );
var key = require( './kms/key.js' );
var keySummary = require( './kms/keySummary.js' );
var keyVersion = require( './kms/keyVersion.js' );
var keyVersionSummary = require( './kms/keyVersionSummary.js' );
var vault = require( './kms/vault.js' );
var vaultSummary = require( './kms/vaultSummary.js' );

module.exports = {
      decryptedData: decryptedData,
      encryptedData: encryptedData,
      generatedKey: generatedKey,
      key: key,
      keySummary: keySummary,
      keyVersion: keyVersion,
      keyVersionSummary: keyVersionSummary,
      vault: vault,
      vaultSummary: vaultSummary
}