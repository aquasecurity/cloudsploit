var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail Encryption',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail encryption at rest is enabled for logs',
	more_info: 'CloudTrail log files contain sensitive information about an account and should be encrypted at risk for additional protection.',
	recommended_action: 'Enable CloudTrail log encryption through the CloudTrail console or API',
	link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.eachLimit(helpers.regions.cloudtrail, helpers.MAX_REGIONS_AT_A_TIME, function(region, cb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var cloudtrail = new AWS.CloudTrail(LocalAWSConfig);

			helpers.cache(cache, cloudtrail, 'describeTrails', function(err, data) {
				if (err) {
					results.push({
						status: 3,
						message: 'Unable to query for CloudTrail encryption status',
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
							if (!data.trailList[t].KmsKeyId) {
								results.push({
									status: 2,
									message: 'CloudTrail encryption is not enabled',
									region: region,
									resource: data.trailList[t].TrailARN
								});
							} else {
								results.push({
									status: 0,
									message: 'CloudTrail encryption is enabled',
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
						message: 'Unable to query for CloudTrail encryption status',
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