var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'Password Policy',
		query: 'passwordPolicy',
		category: 'IAM',
		description: 'Ensures a strong password policy is setup for the account',
		tests: {
			minPasswordLength: {
				title: 'Minimum Password Length',
				description: 'Ensures password policy requires a password of at least 12 characters',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Increase the minimum length requirement for the password policy',
				results: []
			},
			requiresSymbols: {
				title: 'Password Requires Symbols',
				description: 'Ensures password policy requires the use of symbols',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Update the password policy to require the use of symbols',
				results: []
			},
			maxPasswordAge: {
				title: 'Maximum Password Age',
				description: 'Ensures password policy requires passwords to be reset every 180 days',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Descrease the maximum allowed age of passwords for the password policy',
				results: []
			},
			passwordReusePrevention: {
				title: 'Password Reuse Prevention',
				description: 'Ensures password policy prevents previous password reuse',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Increase the minimum previous passwors that can be reused',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {

		var iam = new AWS.IAM(AWSConfig);
		var pluginInfo = getPluginInfo();

		iam.getAccountPasswordPolicy(function(err, data){
			if (err) {
				pluginInfo.tests.minPasswordLength.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				pluginInfo.tests.requiresSymbols.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				pluginInfo.tests.maxPasswordAge.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				pluginInfo.tests.passwordReusePrevention.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				return callback(null, pluginInfo);
			}
			
			if (data) {
				if (data.PasswordPolicy) {
					if (!data.PasswordPolicy.MinimumPasswordLength) {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 2,
							message: 'Password policy does not specify a minimum password length'
						});
					} else if (data.PasswordPolicy.MinimumPasswordLength < 5) {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 2,
							message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is less than 5 characters'
						});
					} else if (data.PasswordPolicy.MinimumPasswordLength < 9) {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 1,
							message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is less than 9 characters'
						});
					} else {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 0,
							message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is suitable'
						});
					}

					if (!data.PasswordPolicy.RequireSymbols) {
						pluginInfo.tests.requiresSymbols.results.push({
							status: 1,
							message: 'Password policy does not require symbols'
						});
					} else {
						pluginInfo.tests.requiresSymbols.results.push({
							status: 0,
							message: 'Password policy requires symbols'
						});
					}

					if (!data.PasswordPolicy.MaxPasswordAge) {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 2,
							message: 'Password policy does not specify a maximum password age'
						});
					} else if (data.PasswordPolicy.MaxPasswordAge > 365) {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 2,
							message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is more than one year'
						});
					} else if (data.PasswordPolicy.MaxPasswordAge > 180) {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 1,
							message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is more than six months'
						});
					} else {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 0,
							message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is suitable'
						});
					}

					if (!data.PasswordPolicy.PasswordReusePrevention) {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 2,
							message: 'Password policy does not prevent previous password reuse'
						});
					} else if (data.PasswordPolicy.PasswordReusePrevention < 2) {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 2,
							message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is less than 2'
						});
					} else if (data.PasswordPolicy.PasswordReusePrevention < 5) {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 1,
							message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is less than 5'
						});
					} else {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 0,
							message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is suitable'
						});
					}
				}
				callback(null, pluginInfo);
			} else {
				pluginInfo.tests.minPasswordLength.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				pluginInfo.tests.requiresSymbols.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				pluginInfo.tests.maxPasswordAge.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				pluginInfo.tests.passwordReusePrevention.results.push({
					status: 3,
					message: 'Unable to query for password policy status'
				});

				return callback(null, pluginInfo);
			}
		});
	}
};