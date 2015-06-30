// TODO: Enable for all regions

var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'CloudTrail Enabled',
		query: 'cloudtrailEnabled',
		category: 'CloudTrail',
		aws_service: 'CloudTrail',
		description: 'Ensures CloudTrail is enabled for all regions within an account',
		more_info: 'User accounts should have an MFA device setup to enable two-factor authentication',
		link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
		tests: {
			cloudtrailEnabled: {
				title: 'CloudTrail Enabled',
				description: 'Ensures CloudTrail is enabled for all regions within an account',
				recommendedAction: 'Enable CloudTrail for all regions',
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

	run: function(AWSConfig, callback) {
		var cloudtrail = new AWS.CloudTrail(AWSConfig);
		var pluginInfo = getPluginInfo();

		cloudtrail.describeTrails({}, function(err, data){
			if (err) {
				pluginInfo.tests.cloudtrailEnabled.results.push({
					status: 3,
					message: 'Unable to query for CloudTrail policy'
				});

				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.trailList) {
				if (!data.trailList.length) {
					pluginInfo.tests.cloudtrailEnabled.results.push({
						status: 2,
						message: 'CloudTrail is not enabled for this account'
					});
				} else if (data.trailList[0] && !data.trailList[0].IncludeGlobalServiceEvents) {
					pluginInfo.tests.cloudtrailEnabled.results.push({
						status: 1,
						message: 'CloudTrail is enabled but does not include global service events'
					});
				} else if (data.trailList[0] && data.trailList[0].IncludeGlobalServiceEvents) {
					pluginInfo.tests.cloudtrailEnabled.results.push({
						status: 0,
						message: 'CloudTrail is enabled and includes global service events'
					});
				} else {
					pluginInfo.tests.cloudtrailEnabled.results.push({
						status: 2,
						message: 'CloudTrail is enabled but is not properly configured'
					});
				}
				callback(null, pluginInfo);
			} else {
				pluginInfo.tests.cloudtrailEnabled.results.push({
					status: 3,
					message: 'Unable to query for CloudTrail policy'
				});

				return callback(null, pluginInfo);
			}
		});
	}
};