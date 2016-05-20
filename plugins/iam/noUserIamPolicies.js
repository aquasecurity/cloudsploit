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
	cis_benchmark: '1.15',

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
				var goodUser = true;
				var userError = false;

				async.parallel([
					function(pCb) {
						// Query for managed policies
						iam.listAttachedUserPolicies({UserName: user.UserName}, function(aupErr, aupData){
							if (aupErr || !aupData || !aupData.AttachedPolicies) {
								userError = true;
								return pCb();
							}

							if (aupData.AttachedPolicies.length) { goodUser = false; }
							pCb();
						});
					},
					function(pCb) {
						// Query for inline policies
						iam.listUserPolicies({UserName: user.UserName}, function(upErr, upData){
							if (upErr || !upData || !upData.PolicyNames) {
								userError = true;
								return pCb();
							}

							if (upData.PolicyNames.length) { goodUser = false; }
							pCb();
						});
					}
				], function(){
					if (userError) {
						results.push({
							status: 3,
							message: 'Unable to query policies for user: ' + user.UserName,
							region: 'global',
							resource: user.Arn
						});

						return cb();
					}

					if (goodUser) {
						results.push({
							status: 0,
							message: 'User is not using attached or inline policies',
							region: 'global',
							resource: user.Arn
						});
					} else {
						results.push({
							status: 1,
							message: 'User is using attached or inline policies',
							region: 'global',
							resource: user.Arn
						});
					}

					cb();
				});
			}, function(err){
				if (err) {
					results.push({
						status: 3,
						message: 'Unable to query for user policies',
						region: 'global'
					});
				}
				callback(null, results);
			});
		});
	}
};