var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Access Keys Rotated',
	category: 'IAM',
	description: 'Ensures access keys are not older than 180 days in order to reduce accidental exposures',
	more_info: 'Access keys should be rotated frequently to avoid having them accidentally exposed.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
	recommended_action: 'To rotate an access key, first create a new key, replace the key and secret throughout your app or scripts, then set the previous key to disabled. Once you ensure that no services are broken, then fully delete the old key.',
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

		function addAccessKeyResults(lastRotated, keyNum, arn, userCreationTime) {
			var returnMsg = 'User access key ' + keyNum + ' ' + ((lastRotated === 'N/A' || !lastRotated) ? 'has never been rotated' : 'was last rotated ' + helpers.functions.daysAgo(lastRotated) + ' days ago');

			if (helpers.functions.daysAgo(userCreationTime) > 180 &&
				(!lastRotated || lastRotated === 'N/A' || helpers.functions.daysAgo(lastRotated) > 180)) {
				helpers.addResult(results, 2, returnMsg, 'global', arn);
			} else if (helpers.functions.daysAgo(userCreationTime) > 90 &&
				(!lastRotated || lastRotated === 'N/A' || helpers.functions.daysAgo(lastRotated) > 90)) {
				helpers.addResult(results, 1, returnMsg, 'global', arn);
			} else {
				helpers.addResult(results, 0,
					'User access key '  + keyNum + ' ' +
					((lastRotated === 'N/A') ? 'has never been rotated but user is only ' + helpers.functions.daysAgo(userCreationTime) + ' days old' : 'was last rotated ' + helpers.functions.daysAgo(lastRotated) + ' days ago'), 'global', arn)
			}

			found = true;
		}

		async.each(generateCredentialReport.data, function(obj, cb){
			// TODO: update to handle booleans
			// The root account security is handled in a different plugin
			if (obj.user === '<root_account>') return cb();

			if (obj.access_key_1_active) {
				addAccessKeyResults(obj.access_key_1_last_rotated, '1', obj.arn, obj.user_creation_time);
			}

			if (obj.access_key_2_active) {
				addAccessKeyResults(obj.access_key_2_last_rotated, '2', obj.arn, obj.user_creation_time);
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