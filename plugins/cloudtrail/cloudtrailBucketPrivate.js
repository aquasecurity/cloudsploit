var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail Bucket Private',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail logging bucket is not publicly accessible',
	more_info: 'CloudTrail buckets contain large amounts of sensitive account data and should only be accessible by logged in users.',
	recommended_action: 'Set the S3 bucket access policy for all CloudTrail buckets to only allow known users to access its files.',
	link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html',
	cis_benchmark: '2.3',

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
						s3.getBucketAcl({Bucket:trailList.S3BucketName}, function(s3err, s3data){

							if (s3err || !s3data) {
								results.push({
									status: 3,
									message: 'Error querying for bucket policy for bucket: ' + trailList.S3BucketName,
									region: region,
									resource: 'arn:aws:s3:::' + trailList.S3BucketName
								});

								return cb();
							}

							var allowsAllUsersTypes = [];

							for (i in s3data.Grants) {
								if (s3data.Grants[i].Grantee.Type &&
									s3data.Grants[i].Grantee.Type === 'Group' &&
									s3data.Grants[i].Grantee.URI &&
									s3data.Grants[i].Grantee.URI.indexOf('AllUsers') > -1
								) {
									allowsAllUsersTypes.push(s3data.Grants[i].Permission);
								}
							}

							if (allowsAllUsersTypes.length) {
								results.push({
									status: 2,
									message: 'Bucket: ' + trailList.S3BucketName + ' allows global access to: ' + allowsAllUsersTypes.concat(', '),
									region: region,
									resource: 'arn:aws:s3:::' + trailList.S3BucketName
								});
							} else {
								results.push({
									status: 0,
									message: 'Bucket: ' + trailList.S3BucketName + ' does not allow public access',
									region: region,
									resource: 'arn:aws:s3:::' + trailList.S3BucketName
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