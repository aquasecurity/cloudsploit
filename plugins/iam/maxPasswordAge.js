var helpers = require('../../helpers');

module.exports = {
	title: 'Maximum Password Age',
	category: 'IAM',
	description: 'Ensures password policy requires passwords to be reset every 180 days',
	more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Descrease the maximum allowed age of passwords for the password policy',
	apis: ['IAM:getAccountPasswordPolicy'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var getAccountPasswordPolicy = helpers.addSource(cache, source,
				['iam', 'getAccountPasswordPolicy', region]);

		if (!getAccountPasswordPolicy) return callback(null, results, source);

		if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
			helpers.addResult(results, 3, 'Unable to query for password policy status');
			return callback(null, results, source);
		}

		if (!getAccountPasswordPolicy.MaxPasswordAge) {
			helpers.addResult(results, 2, 'Password policy does not specify a maximum password age');
		} else if (getAccountPasswordPolicy.MaxPasswordAge > 365) {
			helpers.addResult(results, 2, 'Maximum password age of: ' + getAccountPasswordPolicy.MaxPasswordAge + ' days is more than one year');
		} else if (getAccountPasswordPolicy.MaxPasswordAge > 180) {
			helpers.addResult(results, 1, 'Maximum password age of: ' + getAccountPasswordPolicy.MaxPasswordAge + ' days is more than six months');
		} else {
			helpers.addResult(results, 0, 'Maximum password age of: ' + getAccountPasswordPolicy.MaxPasswordAge + ' days is suitable');
		}

		callback(null, results, source);
	}
};