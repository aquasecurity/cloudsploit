var helpers = require('../../helpers');

module.exports = {
	title: 'Password Reuse Prevention',
	category: 'IAM',
	description: 'Ensures password policy prevents previous password reuse',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Increase the minimum previous passwors that can be reused to 24.',
	apis: ['IAM:getAccountPasswordPolicy'],
	settings: {
		password_reuse_fail: {
			name: 'Password Reuse Fail',
			description: 'Return a failing result when password reuse policy remembers fewer than this many past passwords',
			regex: '^[1-9]{1}[0-9]{0,2}$',
			default: 5
		},
		password_reuse_warn: {
			name: 'Password Reuse Warn',
			description: 'Return a warning result when password reuse policy remembers fewer than this many past passwords',
			regex: '^[1-9]{1}[0-9]{0,2}$',
			default: 24
		}
	},

	run: function(cache, settings, callback) {
		var config = {
			password_reuse_fail: settings.password_reuse_fail || this.settings.password_reuse_fail.default,
			password_reuse_warn: settings.password_reuse_warn || this.settings.password_reuse_warn.default
		};

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};

		var region = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';

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
		} else if (passwordPolicy.PasswordReusePrevention < config.password_reuse_fail) {
			helpers.addResult(results, 2,
				'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than ' + config.password_reuse_fail, 'global', null, custom);
		} else if (passwordPolicy.PasswordReusePrevention < config.password_reuse_warn) {
			helpers.addResult(results, 1,
				'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than ' + config.password_reuse_warn, 'global', null, custom);
		} else {
			helpers.addResult(results, 0,
				'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is suitable', 'global', null, custom);
		}

		callback(null, results, source);
	}
};