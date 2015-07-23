var AWS = require('aws-sdk');
var regions = require(__dirname + '/../../regions.json');
var async = require('async');

function getPluginInfo() {
	return {
		title: 'CloudTrail Enabled',
		query: 'cloudtrailEnabled',
		category: 'CloudTrail',
		description: 'Ensures CloudTrail is enabled for all regions within an account',
		tests: {
			cloudtrailEnabled: {
				title: 'CloudTrail Enabled',
				description: 'Ensures CloudTrail is enabled for all regions within an account',
				more_info: 'CloudTrail should be enabled for all regions in order to detect suspicious activity in regions that are not typically used.',
				link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html',
				recommended_action: 'Enable CloudTrail for all regions',
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
		var pluginInfo = getPluginInfo();

		async.each(regions, function(region, cb){
			// Update the region
			AWSConfig.region = region;
			var cloudtrail = new AWS.CloudTrail(AWSConfig);

			cloudtrail.describeTrails({}, function(err, data){
				if (err) {
					pluginInfo.tests.cloudtrailEnabled.results.push({
						status: 3,
						message: 'Unable to query for CloudTrail policy in region: ' + region,
						region: region
					});

					return cb();
				}

				// Perform checks for establishing if MFA token is enabled
				if (data && data.trailList) {
					if (!data.trailList.length) {
						pluginInfo.tests.cloudtrailEnabled.results.push({
							status: 2,
							message: 'CloudTrail is not enabled for region: ' + region,
							region: region
						});
					} else if (data.trailList[0] && !data.trailList[0].IncludeGlobalServiceEvents) {
						pluginInfo.tests.cloudtrailEnabled.results.push({
							status: 1,
							message: 'CloudTrail is enabled but does not include global service events',
							region: region
						});
					} else if (data.trailList[0] && data.trailList[0].IncludeGlobalServiceEvents) {
						pluginInfo.tests.cloudtrailEnabled.results.push({
							status: 0,
							message: 'CloudTrail is enabled and includes global service events',
							region: region
						});
					} else {
						pluginInfo.tests.cloudtrailEnabled.results.push({
							status: 2,
							message: 'CloudTrail is enabled but is not properly configured',
							region: region
						});
					}
					cb();
				} else {
					pluginInfo.tests.cloudtrailEnabled.results.push({
						status: 3,
						message: 'Unable to query for CloudTrail policy for region: ' + region,
						region: region
					});
					cb();
				}
			});
		}, function(){
			return callback(null, pluginInfo);
		});
	}
};