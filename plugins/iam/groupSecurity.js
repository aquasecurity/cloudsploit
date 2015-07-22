var AWS = require('aws-sdk');
var async = require('async');

function getPluginInfo() {
	return {
		title: 'Group Security',
		query: 'groupSecurity',
		category: 'IAM',
		description: 'Ensures groups contain users and policies',
		tests: {
			emptyGroups: {
				title: 'Empty Groups',
				description: 'Ensures all groups have at least one member',
				more_info: 'While having empty groups does not present a direct security risk, it does broaden the management landscape which could potentially introduce risks in the future.',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_WorkingWithGroupsAndUsers.html',
				recommended_action: 'Remove unused groups without users',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var iam = new AWS.IAM(AWSConfig);
		var pluginInfo = getPluginInfo();

		iam.listGroups({},function(err, data){
			if (err) {
				var returnMsg = {
					status: 3,
					message: 'Unable to query for groups'
				};
				pluginInfo.tests.emptyGroups.results.push(returnMsg);
				
				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.Groups) {
				if (!data.Groups.length) {
					pluginInfo.tests.emptyGroups.results.push({
						status: 0,
						message: 'No groups found'
					});

					return callback(null, pluginInfo);
				}

				async.eachLimit(data.Groups, 5, function(group, cb){
					iam.getGroup({GroupName: group.GroupName}, function(err, data){
						if (err || !data) {
							pluginInfo.tests.emptyGroups.results.push({
								status: 3,
								message: 'Unable to query for group: ' + group.GroupName
							});

							return cb();
						}

						if (!data.Users || !data.Users.length) {
							pluginInfo.tests.emptyGroups.results.push({
								status: 1,
								message: 'Group: ' + group.GroupName + ' does not contain any users'
							});
						} else {
							pluginInfo.tests.emptyGroups.results.push({
								status: 0,
								message: 'Group: ' + group.GroupName + ' contains ' + data.Users.length + ' user(s)'
							});
						}

						cb();
					});
				}, function(){
					return callback(null, pluginInfo);
				});
			} else {
				pluginInfo.tests.emptyGroups.results.push({
					status: 3,
					message: 'Unexpected data when querying groups'
				});

				return callback(null, pluginInfo);
			}
		});
	}
};