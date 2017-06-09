var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'KMS Key Rotation',
	category: 'KMS',
	description: 'Ensures KMS keys are set to rotate on a regular schedule',
	more_info: 'All KMS keys should have key rotation enabled. AWS will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.',
	recommended_action: 'Enable yearly rotation for the KMS key',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html',
	apis: ['KMS:listKeys', 'KMS:describeKey', 'KMS:getKeyRotationStatus'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.kms, function(region, rcb){
			
			var listKeys = helpers.addSource(cache, source,
					['kms', 'listKeys', region]);

			if (!listKeys) return rcb();

			if (listKeys.err || !listKeys.data) {
				helpers.addResult(results, 3,
					'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
				return rcb();
			}

			if (!listKeys.data.length) {
				helpers.addResult(results, 0, 'No KMS keys found', region);
				return rcb();				
			}

			async.each(listKeys.data, function(kmsKey, kcb){
				var describeKey = helpers.addSource(cache, source,
					['kms', 'describeKey', region, kmsKey.KeyId]);

				var getKeyRotationStatus = helpers.addSource(cache, source,
					['kms', 'getKeyRotationStatus', region, kmsKey.KeyId]);

				if (!describeKey || describeKey.err || !describeKey.data) {
					helpers.addResult(results, 3,
						'Unable to describe key: ' + helpers.addError(describeKey),
						region, kmsKey.KeyArn);
					return kcb();
				}

				var describeKeyData = describeKey.data;

				// AWS-generated keys for CodeCommit, ACM, etc. should be skipped.
				// The only way to distinguish these keys is the default description used by AWS.
				// Also skip keys that are being deleted
				if (describeKeyData.KeyMetadata &&
					(describeKeyData.KeyMetadata.Description && describeKeyData.KeyMetadata.Description.indexOf('Default master key that protects my') === 0) ||
					(describeKeyData.KeyMetadata.KeyState && describeKeyData.KeyMetadata.KeyState == 'PendingDeletion')) {
					return kcb();
				}

				var keyRotationStatusData = getKeyRotationStatus.data;

				if (!getKeyRotationStatus || getKeyRotationStatus.err || !getKeyRotationStatus.data) {
					helpers.addResult(results, 3,
						'Unable to get key rotation status: ' + helpers.addError(getKeyRotationStatus),
						region, kmsKey.KeyArn);
					return kcb();
				}

				if (keyRotationStatusData.KeyRotationEnabled) {
					helpers.addResult(results, 0, 'Key rotation is enabled', region, kmsKey.KeyArn);
				} else {
					helpers.addResult(results, 2, 'Key rotation is not enabled', region, kmsKey.KeyArn);
				}

				kcb();
			}, function(){
				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};