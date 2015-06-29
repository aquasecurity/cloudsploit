var pluginInfo = {
	title: 'Password Policy',
	query: 'passwordPolicy',
	category: 'IAM',
	aws_service: 'IAM',
	description: 'Ensures a strong password policy is setup for the account',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	tests: {
		minPasswordLength: {
			title: 'Minimum Password Length',
			description: 'Ensures password policy requires a password of at least 12 characters',
			recommendedAction: 'Increase the minimum length requirement for the password policy',
			results: []
		},
		requiresSymbols: {
			title: 'Password Requires Symbols',
			description: 'Ensures password policy requires the use of symbols',
			recommendedAction: 'Update the password policy to require the use of symbols',
			results: []
		},
		maxPasswordAge: {
			title: 'Maximum Password Age',
			description: 'Ensures password policy requires passwords to be reset every 180 days',
			recommendedAction: 'Descrease the maximum allowed age of passwords for the password policy',
			results: []
		},
		passwordReusePrevention: {
			title: 'Password Reuse Prevention',
			description: 'Ensures password policy prevents previous password reuse',
			recommendedAction: 'Increase the minimum previous passwors that can be reused',
			results: []
		}
	}
};

module.exports = {
	title: pluginInfo.title,
	query: pluginInfo.query,
	category: pluginInfo.category,
	description: pluginInfo.description,
	more_info: pluginInfo.more_info,
	link: pluginInfo.link,

	run: function(AWS, callback) {

		var iam = new AWS.IAM();

		iam.getAccountPasswordPolicy(function(err, data){
			if (err) {
				callback(err);
				return;
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
				callback('unexpected return data');
				return;
			}
		});
	}
};