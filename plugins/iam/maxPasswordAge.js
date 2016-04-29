var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Maximum Password Age',
	category: 'IAM',
	description: 'Ensures password policy requires passwords to be reset every 180 days',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Descrease the maximum allowed age of passwords for the password policy',

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
			
			if (!data.PasswordPolicy.MaxPasswordAge) {
				results.push({
					status: 2,
					message: 'Password policy does not specify a maximum password age',
					region: 'global'
				});
			} else if (data.PasswordPolicy.MaxPasswordAge > 365) {
				results.push({
					status: 2,
					message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is more than one year',
					region: 'global'
				});
			} else if (data.PasswordPolicy.MaxPasswordAge > 180) {
				results.push({
					status: 1,
					message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is more than six months',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is suitable',
					region: 'global'
				});
			}

			callback(null, results);
		});
	}
};