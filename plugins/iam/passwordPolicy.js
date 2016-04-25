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
				description: 'Ensures password policy requires a password of at least 14 characters',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Increase the minimum length requirement for the password policy',
				results: []
			},
			requiresUppercase: {
				title: 'Password Requires Uppercase',
				description: 'Ensures password policy requires at least one uppercase letter',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Update the password policy to require the use of uppercase letters',
				results: []
			},
			requiresLowercase: {
				title: 'Password Requires Lowercase',
				description: 'Ensures password policy requires at least one lowercase letter',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Update the password policy to require the use of lowercase letters',
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
			requiresNumbers: {
				title: 'Password Requires Numbers',
				description: 'Ensures password policy requires the use of numbers',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Update the password policy to require the use of numbers',
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
				recommended_action: 'Increase the minimum previous passwors that can be reused to 24.',
				results: []
			},
			passwordExpiration: {
				title: 'Password Expiration',
				description: 'Ensures password policy enforces a password expiration',
				more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Enable password expiration for the account',
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
				pluginInfo.tests.forEach(function(test){
					test.results.push({
						status: 3,
						message: 'Unable to query for password policy status',
						region: 'global'
					});
				});

				return callback(null, pluginInfo);
			}
			
			if (data) {
				if (data.PasswordPolicy) {
					if (!data.PasswordPolicy.MinimumPasswordLength) {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 2,
							message: 'Password policy does not specify a minimum password length',
							region: 'global'
						});
					} else if (data.PasswordPolicy.MinimumPasswordLength < 10) {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 2,
							message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is less than 10 characters',
							region: 'global'
						});
					} else if (data.PasswordPolicy.MinimumPasswordLength < 14) {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 1,
							message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is less than 14 characters',
							region: 'global'
						});
					} else {
						pluginInfo.tests.minPasswordLength.results.push({
							status: 0,
							message: 'Minimum password length of: ' + data.PasswordPolicy.MinimumPasswordLength + ' is suitable',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.RequireUppercaseCharacters) {
						pluginInfo.tests.requiresUppercase.results.push({
							status: 1,
							message: 'Password policy does not require uppercase characters',
							region: 'global'
						});
					} else {
						pluginInfo.tests.requiresUppercase.results.push({
							status: 0,
							message: 'Password policy requires uppercase characters',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.RequireLowercaseCharacters) {
						pluginInfo.tests.requiresLowercase.results.push({
							status: 1,
							message: 'Password policy does not require lowercase characters',
							region: 'global'
						});
					} else {
						pluginInfo.tests.requiresLowercase.results.push({
							status: 0,
							message: 'Password policy requires lowercase characters',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.RequireSymbols) {
						pluginInfo.tests.requiresSymbols.results.push({
							status: 1,
							message: 'Password policy does not require symbols',
							region: 'global'
						});
					} else {
						pluginInfo.tests.requiresSymbols.results.push({
							status: 0,
							message: 'Password policy requires symbols',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.RequireNumbers) {
						pluginInfo.tests.requiresNumbers.results.push({
							status: 1,
							message: 'Password policy does not require numbers',
							region: 'global'
						});
					} else {
						pluginInfo.tests.requiresNumbers.results.push({
							status: 0,
							message: 'Password policy requires numbers',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.MaxPasswordAge) {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 2,
							message: 'Password policy does not specify a maximum password age',
							region: 'global'
						});
					} else if (data.PasswordPolicy.MaxPasswordAge > 365) {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 2,
							message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is more than one year',
							region: 'global'
						});
					} else if (data.PasswordPolicy.MaxPasswordAge > 180) {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 1,
							message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is more than six months',
							region: 'global'
						});
					} else {
						pluginInfo.tests.maxPasswordAge.results.push({
							status: 0,
							message: 'Maximum password age of: ' + data.PasswordPolicy.MaxPasswordAge + ' days is suitable',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.PasswordReusePrevention) {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 2,
							message: 'Password policy does not prevent previous password reuse',
							region: 'global'
						});
					} else if (data.PasswordPolicy.PasswordReusePrevention < 5) {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 2,
							message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is less than 5',
							region: 'global'
						});
					} else if (data.PasswordPolicy.PasswordReusePrevention < 24) {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 1,
							message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is less than 24',
							region: 'global'
						});
					} else {
						pluginInfo.tests.passwordReusePrevention.results.push({
							status: 0,
							message: 'Maximum password reuse of: ' + data.PasswordPolicy.PasswordReusePrevention + ' passwords is suitable',
							region: 'global'
						});
					}

					if (!data.PasswordPolicy.ExpirePasswords) {
						pluginInfo.tests.passwordExpiration.results.push({
							status: 2,
							message: 'Password expiration policy is not set to expire passwords',
							region: 'global'
						});
					} else if (data.PasswordPolicy.ExpirePasswords < 90) {
						pluginInfo.tests.passwordExpiration.results.push({
							status: 2,
							message: 'Password expiration of: ' + data.PasswordPolicy.ExpirePasswords + ' days is less than 90',
							region: 'global'
						});
					} else if (data.PasswordPolicy.ExpirePasswords < 24) {
						pluginInfo.tests.passwordExpiration.results.push({
							status: 1,
							message: 'Password expiration of: ' + data.PasswordPolicy.ExpirePasswords + ' days is less than 180',
							region: 'global'
						});
					} else {
						pluginInfo.tests.passwordExpiration.results.push({
							status: 0,
							message: 'Password expiration of: ' + data.PasswordPolicy.ExpirePasswords + ' passwords is suitable',
							region: 'global'
						});
					}
				}
				callback(null, pluginInfo);
			} else {
				pluginInfo.tests.forEach(function(test){
					test.results.push({
						status: 3,
						message: 'Unable to query for password policy status',
						region: 'global'
					});
				});

				return callback(null, pluginInfo);
			}
		});
	}
};