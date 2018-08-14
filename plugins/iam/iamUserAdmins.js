var async = require('async');
var helpers = require('../../helpers');

var managedAdminPolicy = 'arn:aws:iam::aws:policy/AdministratorAccess';

module.exports = {
	title: 'IAM User Admins',
	category: 'IAM',
	description: 'Ensures the number of IAM admins in the account are minimized',
	more_info: 'While at least two IAM admin users should be configured, the total number of admins should be kept to a minimum.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.html',
	recommended_action: 'Keep two users with admin permissions but ensure other IAM users have more limited permissions.',
	apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies',
		   'IAM:listGroupsForUser',
		   'IAM:listGroups', 'IAM:listGroupPolicies', 'IAM:listAttachedGroupPolicies',
		   'IAM:getUserPolicy', 'IAM:getGroupPolicy'],
	settings: {
		iam_admin_count: {
			name: 'IAM Admin Count',
			description: 'The number of IAM user admins to require in the account',
			regex: '^[1-9]{1}[0-9]{0,3}$',
			default: 2
		}
	},

	run: function(cache, settings, callback) {
		var config = {
			iam_admin_count: settings.iam_admin_count || this.settings.iam_admin_count.default
		};

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		
		var region = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';

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

		var userAdmins = [];

		async.each(listUsers.data, function(user, cb){
			if (!user.UserName) return cb();

			// Get managed policies attached to user
			var listAttachedUserPolicies = helpers.addSource(cache, source,
					['iam', 'listAttachedUserPolicies', region, user.UserName]);

			// Get inline policies attached to user
			var listUserPolicies = helpers.addSource(cache, source,
					['iam', 'listUserPolicies', region, user.UserName]);

			var listGroupsForUser = helpers.addSource(cache, source,
					['iam', 'listGroupsForUser', region, user.UserName]);

			var getUserPolicy = helpers.addSource(cache, source,
					['iam', 'getUserPolicy', region, user.UserName]);

			if (listAttachedUserPolicies.err) {
				helpers.addResult(results, 3,
					'Unable to query for IAM attached policy for user: ' + user.UserName + ': ' + helpers.addError(listAttachedUserPolicies), 'global', user.Arn);
				return cb();
			}

			if (listUserPolicies.err) {
				helpers.addResult(results, 3,
					'Unable to query for IAM user policy for user: ' + user.UserName + ': ' + helpers.addError(listUserPolicies), 'global', user.Arn);
				return cb();
			}

			if (listGroupsForUser.err) {
				helpers.addResult(results, 3,
					'Unable to query for IAM user groups for user: ' + user.UserName + ': ' + helpers.addError(listGroupsForUser), 'global', user.Arn);
				return cb();
			}

			// See if user has admin managed policy
			if (listAttachedUserPolicies &&
				listAttachedUserPolicies.data &&
				listAttachedUserPolicies.data.AttachedPolicies) {

				for (a in listAttachedUserPolicies.data.AttachedPolicies) {
					var policy = listAttachedUserPolicies.data.AttachedPolicies[a];

					if (policy.PolicyArn === managedAdminPolicy) {
						userAdmins.push({name: user.UserName, arn: user.Arn});
						return cb();
					}
				}
			}

			// See if user has admin inline policy
			if (listUserPolicies &&
				listUserPolicies.data &&
				listUserPolicies.data.PolicyNames) {

				for (p in listUserPolicies.data.PolicyNames) {
					var policy = listUserPolicies.data.PolicyNames[p];

					if (getUserPolicy &&
						getUserPolicy[policy] && 
						getUserPolicy[policy].data &&
						getUserPolicy[policy].data.PolicyDocument) {

						var statements = helpers.normalizePolicyDocument(
							getUserPolicy[policy].data.PolicyDocument);
						if (!statements) break;

						// Loop through statements to see if admin privileges
						for (s in statements) {
							var statement = statements[s];

							if (statement.Effect === 'Allow' &&
								statement.Action.indexOf('*') > -1 &&
								statement.Resource.indexOf('*') > -1) {
								userAdmins.push({name: user.UserName, arn: user.Arn});
								return cb();
							}
						}
					}
				}
			}

			// See if user is in a group allowing admin access
			if (listGroupsForUser &&
				listGroupsForUser.data &&
				listGroupsForUser.data.Groups) {

				for (g in listGroupsForUser.data.Groups) {
					var group = listGroupsForUser.data.Groups[g];

					// Get managed policies attached to group
					var listAttachedGroupPolicies = helpers.addSource(cache, source,
							['iam', 'listAttachedGroupPolicies', region, group.GroupName]);

					// Get inline policies attached to group
					var listGroupPolicies = helpers.addSource(cache, source,
							['iam', 'listGroupPolicies', region, group.GroupName]);
					
					var getGroupPolicy = helpers.addSource(cache, source,
							['iam', 'getGroupPolicy', region, group.GroupName]);

					// See if group has admin managed policy
					if (listAttachedGroupPolicies &&
						listAttachedGroupPolicies.data &&
						listAttachedGroupPolicies.data.AttachedPolicies) {

						for (a in listAttachedGroupPolicies.data.AttachedPolicies) {
							var policy = listAttachedGroupPolicies.data.AttachedPolicies[a];

							if (policy.PolicyArn === managedAdminPolicy) {
								userAdmins.push({name: user.UserName, arn: user.Arn});
								return cb();
							}
						}
					}

					// See if group has admin inline policy
					if (listGroupPolicies &&
						listGroupPolicies.data &&
						listGroupPolicies.data.PolicyNames) {

						for (p in listGroupPolicies.data.PolicyNames) {
							var policy = listGroupPolicies.data.PolicyNames[p];

							if (getGroupPolicy &&
								getGroupPolicy[policy] && 
								getGroupPolicy[policy].data &&
								getGroupPolicy[policy].data.PolicyDocument) {

								var statements = helpers.normalizePolicyDocument(
									getGroupPolicy[policy].data.PolicyDocument);
								if (!statements) break;

								// Loop through statements to see if admin privileges
								for (s in statements) {
									var statement = statements[s];

									if (statement.Effect === 'Allow' &&
										statement.Action.indexOf('*') > -1 &&
										statement.Resource.indexOf('*') > -1) {
										userAdmins.push({name: user.UserName, arn: user.Arn});
										return cb();
									}
								}
							}
						}
					}
				}
			}

			cb();
		}, function(){
			// Use admins array
			if (userAdmins.length < config.iam_admin_count) {
				helpers.addResult(results, 1,
					'There are fewer than ' + config.iam_admin_count + ' IAM user administrators',
					'global', null, custom);
			} else if (userAdmins.length == config.iam_admin_count) {
				helpers.addResult(results, 0,
					'There are ' + config.iam_admin_count + ' IAM user administrators',
					'global', null, custom);
			} else {
				for (u in userAdmins) {
					helpers.addResult(results, 2,
						'User: ' + userAdmins[u].name + ' is one of ' + userAdmins.length + ' IAM user administrators, which exceeds the expected value of: ' + config.iam_admin_count,
						'global', userAdmins[u].arn, custom);
				}
			}

			callback(null, results, source);
		});
	}
};