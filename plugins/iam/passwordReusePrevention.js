var helpers = require('../../helpers');

module.exports = {
	title: 'Password Reuse Prevention',
	category: 'IAM',
	description: 'Ensures password policy prevents previous password reuse',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Increase the minimum previous passwors that can be reused to 24.',
	apis: ['IAM:getAccountPasswordPolicy'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var getAccountPasswordPolicy = helpers.addSource(cache, source,
				['iam', 'getAccountPasswordPolicy', region]);

		if (!getAccountPasswordPolicy) return callback(null, results, source);

		// Handle special case errors
		if (getAccountPasswordPolicy.err &&
			getAccountPasswordPolicy.err.code &&
			getAccountPasswordPolicy.err.code === 'NoSuchEntity') {
			helpers.addResult(results, 2, 'Account does not have a password policy');
			return callback(null, results, source);
		}

		if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
			helpers.addResult(results, 3,
				'Unable to query for password policy status: ' + helpers.addError(getAccountPasswordPolicy));
			return callback(null, results, source);
		}

		var passwordPolicy = getAccountPasswordPolicy.data;

		if (!passwordPolicy.PasswordReusePrevention) {
			helpers.addResult(results, 2, 'Password policy does not previous previous password reuse');
		} else if (passwordPolicy.PasswordReusePrevention < 5) {
			helpers.addResult(results, 2,
				'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than 5');
		} else if (passwordPolicy.PasswordReusePrevention < 24) {
			helpers.addResult(results, 1,
				'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than 24');
		} else {
			helpers.addResult(results, 0,
				'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is suitable');
		}

		callback(null, results, source);
	}
};