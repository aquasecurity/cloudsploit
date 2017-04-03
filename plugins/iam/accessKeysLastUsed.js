var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Access Keys Last Used',
	category: 'IAM',
	description: 'Detects access keys that have not been used for a period of time and that should be decommissioned',
	more_info: 'Having numerous, unused access keys extends the attack surface. Access keys should be removed if they are no longer being used.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
	recommended_action: 'Log into the IAM portal and remove the offending access key.',

	run: function(AWSConfig, cache, includeSource, callback) {

		var results = [];
		var source = {};

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.functions.waitForCredentialReport(iam, function(err, data){
			if (includeSource) source.global = {error: err, data: []};

			if (err || !data || !data.Content) {
				results.push({
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				});

				return callback(null, results, source);
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

				return callback(null, results, source);
			}

			if (includeSource) source.global.data = csvRows;

			if (csvRows.length <= 2) {
				// The only user is the root user
				results.push({
					status: 0,
					message: 'No users using access keys found',
					region: 'global'
				});

				return callback(null, results, source);
			}

			for (r in csvRows) {
				if (r == 0) { continue; }	// Skip the header row

				var csvRow = csvRows[r];
				var csvFields = csvRow.split(',');

				var user = csvFields[0];
				var arn = csvFields[1];
				var accessKey1LastUsed = csvFields[10];
				var accessKey2LastUsed = csvFields[15];

				if (user === '<root_account>') { 
					// The root account security is handled in a different plugin
					continue;
				}

				function addAccessKeyResults(lastUsed, keyNum) {
					var result = {
						status: 0,
						message: 'User access key ' + keyNum + ' ' + ((lastUsed === 'N/A') ? 'has never been used' : 'was last used ' + helpers.functions.daysAgo(lastUsed) + ' days ago'),
						region: 'global',
						resource: arn
					};

					if (helpers.functions.daysAgo(lastUsed) > 180) {
						result.status = 2;
					} else if (helpers.functions.daysAgo(lastUsed) > 90) {
						result.status = 1;
					} else {
						result.message = 'User access key '  + keyNum + ' was last used ' + helpers.functions.daysAgo(lastUsed) + ' days ago';
					}

					results.push(result);
				}

				if (accessKey1LastUsed !== 'N/A') {
					addAccessKeyResults(accessKey1LastUsed, '1');
				}

				if (accessKey2LastUsed  !== 'N/A') {
					addAccessKeyResults(accessKey2LastUsed, '2');
				}
			}

			if (!results.length) {
				results.push({
					status: 0,
					message: 'No users using access keys found',
					region: 'global'
				});
			}

			callback(null, results, source);
		});
	}
};