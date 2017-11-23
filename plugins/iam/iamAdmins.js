var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'IAM User Admins',
	category: 'IAM',
	description: 'Ensures the number of IAM admins in the account are minimized',
	more_info: 'While at least two IAM admin users should be configured, the total number of admins should be kept to a minimum.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.html',
	recommended_action: 'Keep two users with admin permissions but ensure other IAM users have more limited permissions.',
	apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies',
		   'IAM:listGroups', 'IAM:listGroupPolicies', 'IAM:listAttachedGroupPolicies'],

	// If 2 users, mark both as PASS (1 of 2 admins)
	// If > 2, mark all FAIL (1 of 10+ admins)
	// 

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		
		var region = 'us-east-1';

		var listUsers = helpers.addSource(cache, source,
				['iam', 'listUsers', region]);

		if (!listUsers) return callback(null, results, source);

		if (listUsers.err || !listUsers.data) {
			helpers.addResult(results, 3,
				'Unable to query for user IAM policy status: ' + helpers.addError(listUsers));
			return callback(null, results, source);
		}

		if (!listUsers.data.length) {
			helpers.addResult(results, 0, 'No user accounts found');
			return callback(null, results, source);
		}

		async.each(listUsers.data, function(user, cb){
			var goodUser = true;

			if (!user.UserName) return cb();

			var listAttachedUserPolicies = helpers.addSource(cache, source,
					['iam', 'listAttachedUserPolicies', region, user.UserName]);

			var listUserPolicies = helpers.addSource(cache, source,
					['iam', 'listUserPolicies', region, user.UserName]);


			if (!listAttachedUserPolicies) return cb(null, results, source);

			if (listAttachedUserPolicies.err || !listAttachedUserPolicies.data ||
				listUserPolicies.err || !listUserPolicies.data) {
				helpers.addResult(results, 3, 'Unable to query policies for user: ' +
					user.UserName, 'global', user.Arn);
				return cb();
			}

			if ((listAttachedUserPolicies.data.AttachedPolicies &&
				listAttachedUserPolicies.data.AttachedPolicies.length) ||
			   (listUserPolicies.data.PolicyNames &&
				listUserPolicies.data.PolicyNames.length)) {
				helpers.addResult(results, 1, 'User is using attached or inline policies', 'global', user.Arn);
			} else {
				helpers.addResult(results, 0, 'User is not using attached or inline policies', 'global', user.Arn);
			}

			cb();
		}, function(){
			callback(null, results, source);
		});
	}
};