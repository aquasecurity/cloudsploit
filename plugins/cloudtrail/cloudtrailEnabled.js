var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail Enabled',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail is enabled for all regions within an account',
	more_info: 'CloudTrail should be enabled for all regions in order to detect suspicious activity in regions that are not typically used.',
	recommended_action: 'Enable CloudTrail for all regions and ensure that at least one region monitors global service events',
	link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html',
	cis_benchmark: '2.1',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		var globalServicesMonitored = false;

		async.eachLimit(helpers.regions.cloudtrail, helpers.MAX_REGIONS_AT_A_TIME, function(region, cb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var cloudtrail = new AWS.CloudTrail(LocalAWSConfig);

			helpers.cache(cache, cloudtrail, 'describeTrails', function(err, data) {
				if (err) {
					results.push({
						status: 3,
						message: 'Unable to query for CloudTrail policy',
						region: region
					});

					return cb();
				}

				// Perform checks for establishing if MFA token is enabled
				if (data && data.trailList) {
					if (!data.trailList.length) {
						results.push({
							status: 2,
							message: 'CloudTrail is not enabled',
							region: region
						});
					} else if (data.trailList[0]) {
						results.push({
							status: 0,
							message: 'CloudTrail is enabled',
							region: region
						});

						if (data.trailList[0].IncludeGlobalServiceEvents) {
							globalServicesMonitored = true;
						}
					} else {
						results.push({
							status: 2,
							message: 'CloudTrail is enabled but is not properly configured',
							region: region
						});
					}
					cb();
				} else {
					results.push({
						status: 3,
						message: 'Unable to query for CloudTrail policy',
						region: region
					});

					cb();
				}
			});
		}, function(){
			if (!globalServicesMonitored) {
				results.push({
					status: 2,
					message: 'CloudTrail is not monitoring global services',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'CloudTrail is monitoring global services',
					region: 'global'
				});
			}

			return callback(null, results);
		});
	}
};