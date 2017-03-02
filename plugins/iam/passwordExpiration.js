var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Password Expiration',
	category: 'IAM',
	description: 'Ensures password policy enforces a password expiration',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Enable password expiration for the account',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(cache, iam, 'getAccountPasswordPolicy', function(err, data) {
			if (includeSource) source.global = {error: err, data: data};
			
			if (err || !data || !data.PasswordPolicy) {
				results.push({
					status: 3,
					message: 'Unable to query for password policy status',
					region: 'global'
				});

				return callback(null, results, source);
			}
			
			if (!data.PasswordPolicy.ExpirePasswords) {
				results.push({
					status: 2,
					message: 'Password expiration policy is not set to expire passwords',
					region: 'global'
				});
			} else if (data.PasswordPolicy.MaxPasswordAge > 180) {
				results.push({
					status: 2,
					message: 'Password expiration of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is greater than 180',
					region: 'global'
				});
			} else if (data.PasswordPolicy.MaxPasswordAge > 90) {
				results.push({
					status: 1,
					message: 'Password expiration of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is greater than 90',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'Password expiration of: ' + data.PasswordPolicy.MaxPasswordAge + ' passwords is suitable',
					region: 'global'
				});
			}

			callback(null, results, source);
		});
	}
};