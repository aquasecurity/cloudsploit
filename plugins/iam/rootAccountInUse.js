var helpers = require('../../helpers');

module.exports = {
	title: 'Root Account In Use',
	category: 'IAM',
	description: 'Ensures the root account is not being actively used',
	more_info: 'The root account should not be used for day-to-day account management. IAM users, roles, and groups should be used instead.',
	link: 'http://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html',
	recommended_action: 'Create IAM users with appropriate group-level permissions for account access. Create an MFA token for the root account, and store its password and token generation QR codes in a secure place.',
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

				var accessDates = [];

				if (obj.password_last_used && obj.password_last_used !== 'N/A') {
					accessDates.push(obj.password_last_used);
				}

				if (obj.access_key_1_last_used_date && obj.access_key_1_last_used_date !== 'N/A') {
					accessDates.push(obj.access_key_1_last_used_date);
				}

				if (obj.access_key_2_last_used_date && obj.access_key_2_last_used_date !== 'N/A') {
					accessDates.push(obj.access_key_2_last_used_date);
				}

				if (!accessDates.length) {
					helpers.addResult(results, 0, 'Root account has not been used', 'global', obj.arn);
				} else {
					var dateToCompare = helpers.functions.mostRecentDate(accessDates);
					var resultCode = (helpers.functions.daysAgo(dateToCompare) < 15) ? 2: 0;


					helpers.addResult(results, resultCode,
						'Root account was last used ' + helpers.functions.daysAgo(dateToCompare) + ' days ago',
						'global', obj.arn);
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