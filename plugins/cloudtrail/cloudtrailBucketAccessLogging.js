var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail Bucket Access Logging',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail logging bucket has access logging enabled to detect tampering of log files',
	more_info: 'CloudTrail buckets should utilize access logging for an additional layer of auditing. If the log files are deleted or modified in any way, the additional access logs can help determine who made the changes.',
	recommended_action: 'Enable access logging on the CloudTrail bucket from the S3 console',
	link: 'http://docs.aws.amazon.com/AmazonS3/latest/UG/ManagingBucketLogging.html',
	cis_benchmark: '2.6'

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.each(helpers.regions.cloudtrail, function(region, rcb){
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

					return rcb();
				}

				// Perform checks for establishing if MFA token is enabled
				if (data && data.trailList) {
					if (!data.trailList.length) {
						results.push({
							status: 0,
							message: 'No S3 buckets to check',
							region: region
						});
						return rcb();
					}

					delete AWSConfig.region;	// Remove region for S3-specific endpoints
					var s3 = new AWS.S3(AWSConfig);

					async.eachLimit(data.trailList, 10, function(trailList, cb){
						s3.getBucketLogging({Bucket:trailList.S3BucketName}, function(s3err, s3data){
							if (s3data && s3data.LoggingEnabled) {
								results.push({
									status: 0,
									message: 'Bucket: ' + trailList.S3BucketName + ' has S3 access logs enabled',
									region: region,
									resource: trailList.S3BucketName
								});
							} else {
								results.push({
									status: 1,
									message: 'Bucket: ' + trailList.S3BucketName + ' has S3 access logs disabled',
									region: region,
									resource: trailList.S3BucketName
								});
							}
							cb();
						});
					}, function(){
						rcb();
					});
				} else {
					results.push({
						status: 3,
						message: 'Unable to query for CloudTrail policy',
						region: region
					});

					rcb();
				}
			});
		}, function(){
			callback(null, results);
		});
	}
};