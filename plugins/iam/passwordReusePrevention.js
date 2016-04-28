var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Password Reuse Prevention',
	category: 'IAM',
	description: 'Ensures password policy prevents previous password reuse',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Increase the minimum previous passwors that can be reused to 24.',

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
			
			if (!data.PasswordPolicy.PasswordReusePrevention) {
				results.push({
					status: 2,
					message: 'Password policy does not prevent previous password reuse',
					region: 'global'
				});
			} else if (data.PasswordPolicy.PasswordReusePrevention < 5) {
				results.push({
					status: 2,
					message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is less than 24',
					region: 'global'
				});
			} else if (data.PasswordPolicy.PasswordReusePrevention < 24) {
				results.push({
					status: 1,
					message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is less than 24',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is suitable',
					region: 'global'
				});
			}

			callback(null, results);
		});
	}
};