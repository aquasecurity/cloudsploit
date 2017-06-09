var helpers = require('../../helpers');

module.exports = {
	title: 'Root MFA Enabled',
	category: 'IAM',
	description: 'Ensures a multi-factor authentication device is enabled for the root account',
	more_info: 'The root account should have an MFA device setup to enable two-factor authentication.',
	link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
	recommended_action: 'Enable an MFA device for the root account and then use an IAM user for managing services',
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
				'Unable to query for root user: ' + helpers.addError(generateCredentialReport));
			return callback(null, results, source);
		}

		var found = false;

		for (r in generateCredentialReport.data) {
			var obj = generateCredentialReport.data[r];

			if (obj && obj.user === '<root_account>') {
				found = true;

				if (obj.mfa_active) {
					helpers.addResult(results, 0,
						'An MFA device was found for the root account', 'global', obj.arn);
				} else {
					helpers.addResult(results, 2,
						'An MFA device was not found for the root account', 'global', obj.arn);
				}

				break;
			}
		}

		if (!found) {
			helpers.addResult(results, 3, 'Unable to query for root user');
		}

		callback(null, results, source);
	}
};