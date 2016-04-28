var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Root Account In Use',
	category: 'IAM',
	description: 'Ensures the root account is not being actively used',
	more_info: 'The root account should not be used for day-to-day account management. IAM users, roles, and groups should be used instead.',
	link: 'http://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html',
	recommended_action: 'Create IAM users with appropriate group-level permissions for account access. Create an MFA token for the root account, and store its password and token generation QR codes in a secure place.',

	run: function(AWSConfig, callback) {

		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

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
				var userCreated = csvFields[2];
				var passwordLastUsed = csvFields[4];
				var accessKey1LastUsed = csvFields[10];
				var accessKey2LastUsed = csvFields[15];

				if (user === '<root_account>') {
					var accessDates = [];

					if (passwordLastUsed !== 'N/A') { accessDates.push(passwordLastUsed); }
					if (accessKey1LastUsed !== 'N/A') { accessDates.push(accessKey1LastUsed); }
					if (accessKey2LastUsed !== 'N/A') { accessDates.push(accessKey2LastUsed); }

					if (!accessDates.length) {
						results.push({
							status: 0,
							message: 'Root account has not been used',
							region: 'global',
							resource: arn
						});

						break;
					}

					var dateToCompare = helpers.functions.mostRecentDate(accessDates);

					results.push({
						status: (helpers.functions.daysAgo(dateToCompare) < 30) ? 2: 0,
						message: 'Root account was last used ' + helpers.functions.daysAgo(dateToCompare) + ' days ago',
						region: 'global',
						resource: arn
					});

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