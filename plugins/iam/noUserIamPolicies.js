var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'No User IAM Policies',
	category: 'IAM',
	description: 'Ensures IAM policies are not connected directly to IAM users',
	more_info: 'To reduce management complexity, IAM permissions should only be assigned to roles and groups. Users can then be added to those groups. Policies should not be applied directly to a user.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions',
	recommended_action: 'Create groups with the required policies, move the IAM users to the applicable groups, and then remove the inline and directly attached policies from the IAM user.',

	run: function(AWSConfig, callback) {
		var results = [];
		
		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(iam, 'listUsers', function(err, data) {
			if (err || !data || !data.Users) {
				results.push({
					status: 3,
					message: 'Unable to query for user IAM policy status',
					region: 'global'
				});

				return callback(null, results);
			}

			if (!data.Users.length) {
				results.push({
					status: 0,
					message: 'No user accounts found',
					region: 'global'
				});
				
				return callback(null, results);
			}

			async.eachLimit(data.Users, 20, function(user, cb){
				
				iam.listMFADevices({UserName: user.UserName}, function(mfaErr, mfaData){
					if (mfaErr) {
						results.push({
							status: 3,
							message: 'Unable to query MFA device for user: ' + user.UserName,
							region: 'global',
							resource: user.Arn
						});
					} else {
						if (mfaData && mfaData.MFADevices) {
							if (mfaData.MFADevices.length) {
								results.push({
									status: 0,
									message: 'User: ' + user.UserName + ' has an MFA device',
									region: 'global',
									resource: user.Arn
								});
							} else {
								results.push({
									status: 1,
									message: 'User: ' + user.UserName + ' does not have an MFA device enabled',
									region: 'global',
									resource: user.Arn
								});
							}
						}
					}
					cb();
				});
			}, function(err){
				if (err) {
					results.push({
						status: 3,
						message: 'Unable to query for user MFA status',
						region: 'global'
					});
				}
				callback(null, results);
			});
		});
	}
};