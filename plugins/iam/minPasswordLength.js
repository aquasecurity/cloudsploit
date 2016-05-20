var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Minimum Password Length',
	category: 'IAM',
	description: 'Ensures password policy requires a password of at least 14 characters',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Increase the minimum length requirement for the password policy',
	cis_benchmark: '1.9',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(cache, iam, 'getAccountPasswordPolicy', function(err, data) {
			if (err || !data || !data.PasswordPolicy) {
				results.push({
					status: 3,
					message: 'Unable to query for password policy status',
					region: 'global'
				});

				return callback(null, results);
			}
			
			if (!data.PasswordPolicy.MinimumPasswordLength) {
				results.push({
					status: 2,
					message: 'Password policy does not specify a minimum password length',
					region: 'global'
				});
			} else if (data.PasswordPolicy.MinimumPasswordLength < 10) {
				results.push({
					status: 2,
					message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is less than 10 characters',
					region: 'global'
				});
			} else if (data.PasswordPolicy.MinimumPasswordLength < 14) {
				results.push({
					status: 1,
					message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is less than 14 characters',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is suitable',
					region: 'global'
				});
			}

			callback(null, results);
		});
	}
};