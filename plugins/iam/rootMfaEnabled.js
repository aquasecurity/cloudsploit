var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Root MFA Enabled',
	category: 'IAM',
	description: 'Ensures a multi-factor authentication device is enabled for the root account',
	more_info: 'The root account should have an MFA device setup to enable two-factor authentication.',
	link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
	recommended_action: 'Enable an MFA device for the root account and then use an IAM user for managing services',

	run: function(AWSConfig, callback) {

		var results = [];

		var iam = new AWS.IAM(AWSConfig);

		helpers.functions.waitForCredentialReport(iam, function(err, data){
			if (err || !data || !data.Content) {
				results.push({
					status: 3,
					message: 'Unable to query for root user',
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
					message: 'Unable to query for root user',
					region: 'global'
				});

				return callback(null, results);
			}

			for (r in csvRows) {
				if (r == 0) { continue; }	// Skip the header row

				var csvRow = csvRows[r];
				var csvFields = csvRow.split(',');

				var user = csvFields[0];
				var arn = csvFields[1];
				var mfaEnabled = csvFields[7];

				if (user === '<root_account>') { 
					if (mfaEnabled === 'true') {
						results.push({
							status: 0,
							message: 'An MFA device was found for the root account',
							region: 'global',
							resource: arn
						});
					} else {
						results.push({
							status: 2,
							message: 'An MFA device was not found for the root account',
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

			callback(null, results);
		});
	}
};