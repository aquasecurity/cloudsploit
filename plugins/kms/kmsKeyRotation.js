var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'KMS Key Rotation',
	category: 'KMS',
	description: 'Ensures KMS keys are set to rotate on a regular schedule',
	more_info: 'All KMS keys should have key rotation enabled. AWS will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.',
	recommended_action: 'Enable yearly rotation for the KMS key',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html',
	cis_benchmark: '2.8',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.eachLimit(helpers.regions.kms, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var kms = new AWS.KMS(LocalAWSConfig);

			kms.listKeys({Limit: 1000}, function(listKeysErr, listKeysData){
				if (listKeysErr || !listKeysData) {
					results.push({
						status: 3,
						message: 'Unable to query for KMS keys',
						region: region
					});

					return rcb();
				}

				if (!listKeysData.Keys || !listKeysData.Keys.length) {
					results.push({
						status: 0,
						message: 'No KMS keys found',
						region: region
					});

					return rcb();
				}

				async.eachLimit(listKeysData.Keys, 5, function(kmsKey, keyCb){

					kms.describeKey({KeyId: kmsKey.KeyId}, function(describeKeyErr, describeKeyData){
						if (describeKeyErr || !describeKeyData) {
							results.push({
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
								results.push({
									status: 3,
									message: 'Unable to get KMS key rotation status',
									region: region,
									resource: describeKeyData.KeyMetadata.Arn
								});
							} else if (keyRotationStatusData.KeyRotationEnabled) {
								results.push({
									status: 0,
									message: 'Key rotation is enabled',
									region: region,
									resource: describeKeyData.KeyMetadata.Arn
								});
							} else {
								results.push({
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
			callback(null, results);
		});
	}
};