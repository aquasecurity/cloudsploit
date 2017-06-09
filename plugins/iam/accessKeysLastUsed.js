var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Access Keys Last Used',
	category: 'IAM',
	description: 'Detects access keys that have not been used for a period of time and that should be decommissioned',
	more_info: 'Having numerous, unused access keys extends the attack surface. Access keys should be removed if they are no longer being used.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
	recommended_action: 'Log into the IAM portal and remove the offending access key.',
	apis: ['IAM:generateCredentialReport'],

	run: function(cache, callback) {

		var results = [];
		var source = {};

		var region = 'us-east-1';

		var generateCredentialReport = helpers.addSource(cache, source,
				['iam', 'generateCredentialReport', region]);

		if (!generateCredentialReport) return callback(null, results, source);

		if (generateCredentialReport.err || !generateCredentialReport.data) {
			helpers.addResult(results, 3,
				'Unable to query for users: ' + helpers.addError(generateCredentialReport));
			return callback(null, results, source);
		}

		if (generateCredentialReport.data.length <= 2) {
			helpers.addResult(results, 0, 'No users using access keys found');
			return callback(null, results, source);
		}

		var found = false;

		function addAccessKeyResults(lastUsed, keyNum, arn) {
			if (!lastUsed) {
				helpers.addResult(results, 0,
					'User access key '  + keyNum + ' has never been used', 'global', arn);
			} else {
				var returnMsg = 'User access key ' + keyNum + ': was last used ' + helpers.functions.daysAgo(lastUsed) + ' days ago';

				if (helpers.functions.daysAgo(lastUsed) > 180) {
					helpers.addResult(results, 2, returnMsg, 'global', arn)
				} else if (helpers.functions.daysAgo(lastUsed) > 90) {
					helpers.addResult(results, 1, returnMsg, 'global', arn)
				} else {
					helpers.addResult(results, 0,
						'User access key '  + keyNum + ' was last used ' +
						helpers.functions.daysAgo(lastUsed) + ' days ago', 'global', arn);
				}
			}

			found = true;
		}

		async.each(generateCredentialReport.data, function(obj, cb){
			// The root account security is handled in a different plugin
			if (obj.user === '<root_account>') return cb();

			if (obj.access_key_1_active) {
				addAccessKeyResults(obj.access_key_1_last_used_date, '1', obj.arn);
			}

			if (obj.access_key_2_active) {
				addAccessKeyResults(obj.access_key_2_last_used_date, '2', obj.arn);
			}

			cb();
		}, function(){
			if (!found) {
				helpers.addResult(results, 0, 'No users using access keys found');
			}

			callback(null, results, source);
		});
	}
};