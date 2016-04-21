var async = require('async');
var AWS = require('aws-sdk');
var regions = require(__dirname + '/../../regions.json');

function getPluginInfo() {
	return {
		title: 'KMS Keys',
		query: 'kmsKeys',
		category: 'KMS',
		description: 'Ensures KMS keys have proper security controls in place',
		tests: {
			kmsKeyRotation: {
				title: 'KMS Key Rotation',
				description: 'Ensures KMS keys are set to rotate on a regular schedule',
				more_info: 'All KMS keys should have key rotation enabled. AWS will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.',
				recommended_action: 'Enable yearly rotation for the KMS key',
				link: 'http://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var pluginInfo = getPluginInfo();

		async.each(regions, function(region, rcb){
			// Update the region
			AWSConfig.region = region;
			var kms = new AWS.KMS(AWSConfig);

			kms.listKeys({Limit: 1000}, function(listKeysErr, listKeysData){
				if (listKeysErr || !listKeysData) {
					pluginInfo.tests.kmsKeyRotation.results.push({
						status: 3,
						message: 'Unable to query for KMS keys',
						region: region
					});

					return rcb();
				}

				if (!listKeysData.Keys || !listKeysData.Keys.length) {
					pluginInfo.tests.kmsKeyRotation.results.push({
						status: 0,
						message: 'No KMS keys found',
						region: region
					});

					return rcb();
				}

				async.eachLimit(listKeysData.Keys, 5, function(kmsKey, keyCb){

					kms.describeKey({KeyId: kmsKey.KeyId}, function(describeKeyErr, describeKeyData){
						if (describeKeyErr || !describeKeyData) {
							pluginInfo.tests.kmsKeyRotation.results.push({
								status: 3,
								message: 'Unable to describe KMS key: ' + kmsKey.KeyId,
								region: region
							});

							return keyCb();
						}

						// AWS-generated keys for CodeCommit, ACM, etc. should be skipped.
						// The only way to distinguish these keys is the default description used by AWS.
						// Also skip keys that are being deleted
						if (describeKeyData.KeyMetadata &&
							(describeKeyData.KeyMetadata.Description && describeKeyData.KeyMetadata.Description.indexOf('Default master key that protects my') === 0) ||
							(describeKeyData.KeyMetadata.KeyState && describeKeyData.KeyMetadata.KeyState == 'PendingDeletion')) {
							return keyCb();
						}

						// Now check the rotation status
						kms.getKeyRotationStatus({KeyId: kmsKey.KeyId}, function(keyRotationStatusErr, keyRotationStatusData){
							if (keyRotationStatusErr || !keyRotationStatusData) {
								pluginInfo.tests.kmsKeyRotation.results.push({
									status: 3,
									message: 'Unable to get KMS key rotation status',
									region: region,
									resource: describeKeyData.KeyMetadata.Arn
								});
							} else if (keyRotationStatusData.KeyRotationEnabled) {
								pluginInfo.tests.kmsKeyRotation.results.push({
									status: 0,
									message: 'Key rotation is enabled',
									region: region,
									resource: describeKeyData.KeyMetadata.Arn
								});
							} else {
								pluginInfo.tests.kmsKeyRotation.results.push({
									status: 2,
									message: 'Key rotation is not enabled',
									region: region,
									resource: describeKeyData.KeyMetadata.Arn
								});
							}

							keyCb();
						});
					});
				}, function(){
					rcb();
				});
			});
		}, function(){
			callback(null, pluginInfo);
		});
	}
};