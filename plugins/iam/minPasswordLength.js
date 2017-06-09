var helpers = require('../../helpers');

module.exports = {
	title: 'Minimum Password Length',
	category: 'IAM',
	description: 'Ensures password policy requires a password of at least 14 characters',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Increase the minimum length requirement for the password policy',
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

		if (!passwordPolicy.MinimumPasswordLength) {
			helpers.addResult(results, 2, 'Password policy does not specify a minimum password length');
		} else if (passwordPolicy.MinimumPasswordLength < 10) {
			helpers.addResult(results, 2, 'Minimum password length of: ' + passwordPolicy.MinimumPasswordLength + ' is less than 10 characters');
		} else if (passwordPolicy.MinimumPasswordLength < 14) {
			helpers.addResult(results, 1, 'Minimum password length of: ' + passwordPolicy.MinimumPasswordLength + ' is less than 14 characters');
		} else {
			helpers.addResult(results, 0, 'Minimum password length of: ' + passwordPolicy.MinimumPasswordLength + ' is suitable');
		}

		callback(null, results, source);
	}
};