// TODO: Enable for all regions

var pluginInfo = {
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

module.exports = {
	title: pluginInfo.title,
	query: pluginInfo.query,
	category: pluginInfo.category,
	description: pluginInfo.description,
	more_info: pluginInfo.more_info,
	link: pluginInfo.link,

	run: function(AWS, callback) {
		var cloudtrail = new AWS.CloudTrail();

		cloudtrail.describeTrails({}, function(err, data){
			if (err) {
				callback(err);
				return;
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
				callback('unexpected return data');
				return;
			}
		});
	}
};