var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Users MFA Enabled',
	category: 'IAM',
	description: 'Ensures a multi-factor authentication device is enabled for all users within the account',
	more_info: 'User accounts should have an MFA device setup to enable two-factor authentication',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	recommended_action: 'Enable an MFA device for the user account',
	cis_benchmark: '1.2',

	run: function(AWSConfig, cache, callback) {
		var results = [];
		
		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(cache, iam, 'listUsers', function(err, data) {
			if (err || !data || !data.Users) {
				results.push({
					status: 3,
					message: 'Unable to query for user MFA status',
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
				if (!user.PasswordLastUsed) {
					// Skip users without passwords since they won't be logging into the console
					return cb();
				}
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

				if (!results.length) {
					results.push({
						status: 0,
						message: 'No users with passwords requiring MFA found',
						region: 'global'
					});
				}

				callback(null, results);
			});
		});
	}
};