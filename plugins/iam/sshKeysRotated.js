var helpers = require('../../helpers');

module.exports = {
	title: 'SSH Keys Rotated',
	category: 'IAM',
	description: 'Ensures SSH keys are not older than 180 days in order to reduce accidental exposures',
	more_info: 'SSH keys should be rotated frequently to avoid having them accidentally exposed.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html',
	recommended_action: 'To rotate an SSH key, first create a new public-private key pair, then upload the public key to AWS and delete the old key.',
	apis: ['IAM:generateCredentialReport'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var generateCredentialReport = helpers.addSource(cache, source,
				['iam', 'generateCredentialReport', region]);

		if (!generateCredentialReport) return callback(null, results, source);

		if (generateCredentialReport.err || !generateCredentialReport.data) {
			helpers.addResult(results, 3,
				'Unable to query for users: ' + helpers.addError(generateCredentialReport));
			return callback(null, results, source);
		}

		if (generateCredentialReport.data.length === 1) {
			// Only have the root user
			helpers.addResult(results, 0, 'No user accounts with SSH keys found');
			return callback(null, results, source);
		}

		var found = false;

		function addSSHKeyResults(lastRotated, keyNum, arn, userName, userCreationTime) {
			var keyDate = new Date(lastRotated);
			var daysOld = helpers.functions.daysAgo(keyDate);

			var returnMsg = 'SSH key: ' + keyNum + ' for user: ' + userName +
							' is ' + daysOld + ' days old';

			if (helpers.functions.daysAgo(userCreationTime) > 180 &&
				(!lastRotated || lastRotated === 'N/A' || helpers.functions.daysAgo(lastRotated) > 360)) {
				helpers.addResult(results, 2, returnMsg, 'global', arn);
			} else if (helpers.functions.daysAgo(userCreationTime) > 90 &&
				(!lastRotated || lastRotated === 'N/A' || helpers.functions.daysAgo(lastRotated) > 180)) {
				helpers.addResult(results, 1, returnMsg, 'global', arn);
			} else {
				helpers.addResult(results, 0,
					'User SSH key '  + keyNum + ' ' +
					((lastRotated === 'N/A' || !lastRotated) ? 'has never been rotated but user is only ' + helpers.functions.daysAgo(userCreationTime) + ' days old' : 'was last rotated ' + helpers.functions.daysAgo(lastRotated) + ' days ago'), 'global', arn);
			}

			found = true;
		}

		for (r in generateCredentialReport.data) {
			var obj = generateCredentialReport.data[r];

			// TODO: test the root account?
			// if (obj.user === '<root_account>') continue;

			if (obj.cert_1_active) {
				addSSHKeyResults(obj.cert_1_last_rotated, '1', obj.arn, obj.user, obj.user_creation_time);
			}

			if (obj.cert_2_active) {
				addSSHKeyResults(obj.cert_2_last_rotated, '2', obj.arn, obj.user, obj.user_creation_time);
			}
		}

		if (!found) {
			helpers.addResult(results, 0, 'No SSH keys found');
		}

		callback(null, results, source);
	}
};