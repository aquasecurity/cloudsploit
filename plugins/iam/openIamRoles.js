var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Open IAM Roles',
	category: 'IAM',
	description: 'Ensures IAM role trust policies do not allow everyone to assume the role',
	more_info: 'IAM role trust policies should trust specific AWS services, users, roles, identity providers, or accounts. Trusting `*` allows any AWS user to discover and assume that role.',
	link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html',
	recommended_action: 'Limit the trust policy statements on the role such that only desired users, roles, identity providers, or AWS accounts can assume the role',
	apis: ['IAM:listRoles'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		
		var region = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
		var listRoles = helpers.addSource(cache, source,
				['iam', 'listRoles', region]);

		if (!listRoles) return callback(null, results, source);

		if (listRoles.err || !listRoles.data) {
			helpers.addResult(results, 3,
				'Unable to query for IAM role status: ' + helpers.addError(listRoles));
			return callback(null, results, source);
		}

		if (!listRoles.data.length) {
			helpers.addResult(results, 0, 'No IAM roles found');
			return callback(null, results, source);
		}

		async.each(listRoles.data, function(role, cb){
			if(!role.AssumeRolePolicyDocument) return cb();

			var trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
			for (let statement of trustPolicy.Statement) {
				if (statement.Effect !== 'Allow' || !statement.Principal.AWS) continue;

				if (!Array.isArray(statement.Principal.AWS)) {
					statement.Principal.AWS = [statement.Principal.AWS];
				}

				if (statement.Principal.AWS.includes('*')) {
					helpers.addResult(results, 2, 'Role trust policy allows any AWS user to assume', 'global', role.Arn);
				}
			}

			cb();
		}, function(){
			callback(null, results, source);
		});
	}
};