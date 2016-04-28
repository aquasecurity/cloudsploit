var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Password Requires Lowercase',
	category: 'IAM',
	description: 'Ensures password policy requires at least one lowercase letter',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Update the password policy to require the use of lowercase letters',

	run: function(AWSConfig, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(iam, 'getAccountPasswordPolicy', function(err, data) {
			if (err || !data || !data.PasswordPolicy) {
				results.push({
					status: 3,
					message: 'Unable to query for password policy status',
					region: 'global'
				});

				return callback(null, results);
			}
			
			if (!data.PasswordPolicy.RequireLowercaseCharacters) {
				results.push({
					status: 1,
					message: 'Password policy does not require lowercase characters',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'Password policy requires lowercase characters',
					region: 'global'
				});
			}

			callback(null, results);
		});
	}
};