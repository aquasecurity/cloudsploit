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

	run: function(AWSConfig, callback) {

		var results = [];

		var iam = new AWS.IAM(AWSConfig);

		helpers.functions.waitForCredentialReport(iam, function(err, data){
			if (err || !data || !data.Content) {
				results.push({
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				});

				return callback(null, results);
			}

			try {
				var csvContent = data.Content.toString();
				var csvRows = csvContent.split('\n');
			} catch(e) {
				results.push({
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				});

				return callback(null, results);
			}

			if (csvRows.length <= 2) {
				// The only user is the root user
				results.push({
					status: 0,
					message: 'No users using access keys found',
					region: 'global'
				});

				return callback(null, results);
			}

			for (r in csvRows) {
				if (r == 0) {continue; }	// Skip the header row

				var csvRow = csvRows[r];
				var csvFields = csvRow.split(',');

				var user = csvFields[0];
				var arn = csvFields[1];
				var userCreationTime = csvFields[2];
				var accessKey1Active = csvFields[8];
				var accessKey1LastRotated = csvFields[9];
				var accessKey2Active = csvFields[13];
				var accessKey2LastRotated = csvFields[14];

				if (accessKey1Active === 'false' && accessKey2Active === 'false') {
					// User is not using access keys, skip
					continue;
				}

				if (user === '<root_account>') { 
					// The root account security is handled in a different plugin
					continue;
				}

				function addAccessKeyResults(lastRotated, keyNum) {
					var result = {
						status: 0,
						message: 'User access key ' + keyNum + ' ' + ((lastRotated === 'N/A') ? 'has never been rotated' : 'was last rotated ' + helpers.functions.daysAgo(lastRotated) + ' days ago'),
						region: 'global',
						resource: arn
					};

					if (helpers.functions.daysAgo(userCreationTime) > 180 &&
						(lastRotated === 'N/A' || helpers.functions.daysAgo(lastRotated) > 180)) {
						result.status = 2;
					} else if (helpers.functions.daysAgo(userCreationTime) > 90 &&
						(lastRotated === 'N/A' || helpers.functions.daysAgo(lastRotated) > 90)) {
						result.status = 1;
					} else {
						result.message = 'User access key '  + keyNum + ' ' + ((lastRotated === 'N/A') ? 'has never been rotated but user is only ' + helpers.functions.daysAgo(userCreationTime) + ' days old' : 'was last rotated ' + helpers.functions.daysAgo(lastRotated) + ' days ago');
					}

					results.push(result);
				}

				if (accessKey1Active === 'true') {
					addAccessKeyResults(accessKey1LastRotated, '1');
				}

				if (accessKey2Active === 'true') {
					addAccessKeyResults(accessKey2LastRotated, '2');
				}
			}

			if (!results.length) {
				results.push({
					status: 0,
					message: 'No users using access keys found',
					region: 'global'
				});
			}

			callback(null, results);
		});
	}
};