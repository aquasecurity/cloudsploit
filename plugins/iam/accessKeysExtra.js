var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Access Keys Extra',
	category: 'IAM',
	description: 'Detects the use of more than one access key by any single user',
	more_info: 'Having more than one access key for a single user increases the chance of accidental exposure. Each account should only have one key that defines the users permissions.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
	recommended_action: 'Remove the extra access key for the specified user.',

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
				var accessKey1Active = csvFields[8];
				var accessKey2Active = csvFields[13];

				if (user === '<root_account>') { 
					// The root account security is handled in a different plugin
					continue;
				}

				if (accessKey1Active === 'true' && accessKey2Active === 'true') {
					results.push({
						status: 2,
						message: 'User is using both access keys',
						region: 'global',
						resource: arn
					});
				} else {
					results.push({
						status: 0,
						message: 'User is not using both access keys',
						region: 'global',
						resource: arn
					});
				}
			}

			if (!results.length) {
				results.push({
					status: 0,
					message: 'No users using both access keys found',
					region: 'global'
				});
			}

			callback(null, results, source);
		});
	}
};