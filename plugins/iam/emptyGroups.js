var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Empty Groups',
	category: 'IAM',
	description: 'Ensures all groups have at least one member',
	more_info: 'While having empty groups does not present a direct security risk, it does broaden the management landscape which could potentially introduce risks in the future.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_WorkingWithGroupsAndUsers.html',
	recommended_action: 'Remove unused groups without users',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);
		
		helpers.cache(cache, iam, 'listGroups', function(err, data) {
			if (err || !data || !data.Groups) {
				results.push({
					status: 3,
					message: 'Unable to query for groups',
					region: 'global'
				});
				
				return callback(null, results);
			}

			if (!data.Groups.length) {
				results.push({
					status: 0,
					message: 'No groups found',
					region: 'global'
				});

				return callback(null, results);
			}

			async.eachLimit(data.Groups, 20, function(group, cb){
				iam.getGroup({GroupName: group.GroupName}, function(err, data){
					if (err || !data || !data.Users) {
						results.push({
							status: 3,
							message: 'Unable to query for group: ' + group.GroupName,
							region: 'global',
							resource: group.Arn
						});

						return cb();
					}

					if (!data.Users.length) {
						results.push({
							status: 1,
							message: 'Group: ' + group.GroupName + ' does not contain any users',
							region: 'global',
							resource: group.Arn
						});
					} else {
						results.push({
							status: 0,
							message: 'Group: ' + group.GroupName + ' contains ' + data.Users.length + ' user(s)',
							region: 'global',
							resource: group.Arn
						});
					}

					cb();
				});
			}, function(){
				callback(null, results);
			});
		});
	}
};