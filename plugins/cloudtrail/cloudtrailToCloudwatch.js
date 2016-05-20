var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail To CloudWatch',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail logs are being properly delivered to CloudWatch',
	more_info: 'Sending CloudTrail logs to CloudWatch enables easy integration with AWS CloudWatch alerts, as well as an additional backup log storage location.',
	recommended_action: 'Enable CloudTrail CloudWatch integration for all regions',
	link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html',
	cis_benchmark: '2.4',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.each(helpers.regions.cloudtrail, function(region, cb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var cloudtrail = new AWS.CloudTrail(LocalAWSConfig);

			helpers.cache(cache, cloudtrail, 'describeTrails', function(err, data) {
				if (err) {
					results.push({
						status: 3,
						message: 'Unable to query for CloudTrail CloudWatch integration status',
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
						for (t in data.trailList) {
							if (!data.trailList[t].CloudWatchLogsLogGroupArn) {
								results.push({
									status: 2,
									message: 'CloudTrail CloudWatch integration is not enabled',
									region: region,
									resource: data.trailList[t].TrailARN
								});
							} else {
								results.push({
									status: 0,
									message: 'CloudTrail CloudWatch integration is enabled',
									region: region,
									resource: data.trailList[t].TrailARN
								});
							}
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
						message: 'Unable to query for CloudTrail CloudWatch integration status',
						region: region
					});

					cb();
				}
			});
		}, function(){
			callback(null, results);
		});
	}
};