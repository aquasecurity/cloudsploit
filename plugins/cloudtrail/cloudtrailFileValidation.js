var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail File Validation',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail file validation is enabled for all regions within an account',
	more_info: 'CloudTrail file validation is essentially a hash of the file which can be used to ensure its integrity in the case of an account compromise.',
	recommended_action: 'Enable CloudTrail file validation for all regions',
	link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html',

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
						message: 'Unable to query for CloudTrail file validation status',
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
							if (!data.trailList[t].LogFileValidationEnabled) {
								results.push({
									status: 2,
									message: 'CloudTrail log file validation is not enabled',
									region: region,
									resource: data.trailList[t].TrailARN
								});
							} else {
								results.push({
									status: 0,
									message: 'CloudTrail log file validation is enabled',
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
						message: 'Unable to query for CloudTrail file validation status',
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