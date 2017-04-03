var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Root Access Keys',
	category: 'IAM',
	description: 'Ensures the root account is not using access keys',
	more_info: 'The root account should avoid using access keys. Since the root account has full permissions across the entire account, creating access keys for it only increases the chance that they are compromised. Instead, create IAM users with predefined roles.',
	link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
	recommended_action: 'Remove access keys for the root account and setup IAM users with limited permissions instead',

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
					message: 'Unable to query for root user',
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
					message: 'Unable to query for root user',
					region: 'global'
				});

				return callback(null, results, source);
			}

			if (includeSource) source.global.data = csvRows;

			for (r in csvRows) {
				if (r == 0) { continue; }	// Skip the header row

				var csvRow = csvRows[r];
				var csvFields = csvRow.split(',');

				var user = csvFields[0];
				var arn = csvFields[1];
				var accessKey1Active = csvFields[8];
				var accessKey2Active = csvFields[13];

				if (user === '<root_account>') {
					if (accessKey1Active === 'false' && accessKey2Active === 'false') {
						results.push({
							status: 0,
							message: 'Access keys were not found for the root account',
							region: 'global',
							resource: arn
						});
					} else {
						results.push({
							status: 2,
							message: 'Access keys were found for the root account',
							region: 'global',
							resource: arn
						});
					}

					break;	
				}
			}

			if (!results.length) {
				results.push({
					status: 0,
					message: 'Unable to query for root user',
					region: 'global'
				});
			}

			callback(null, results, source);
		});
	}
};