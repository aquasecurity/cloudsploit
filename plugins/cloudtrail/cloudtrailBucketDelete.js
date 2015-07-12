// TODO: Enable for all regions

var async = require('async');
var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'CloudTrail Bucket Delete Policy',
		query: 'cloudtrailBucketDelete',
		category: 'CloudTrail',
		description: 'Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token',
		tests: {
			cloudtrailBucketDelete: {
				title: 'CloudTrail Bucket Delete Policy',
				description: 'Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token',
				more_info: 'To provide additional security, CloudTrail logging buckets should require an MFA token to delete objects',
				recommended_action: 'Enable MFA delete on the CloudTrail bucket',
				link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete',
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
		var cloudtrail = new AWS.CloudTrail(AWSConfig);
		var pluginInfo = getPluginInfo();

		cloudtrail.describeTrails({}, function(err, data){
			if (err) {
				pluginInfo.tests.cloudtrailBucketDelete.results.push({
					status: 3,
					message: 'Unable to query for CloudTrail policy'
				});

				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.trailList) {
				if (!data.trailList.length) {
					pluginInfo.tests.cloudtrailBucketDelete.results.push({
						status: 0,
						message: 'No S3 buckets to check'
					});
					callback(null, pluginInfo);
				} else {
					var s3 = new AWS.S3();

					async.eachLimit(data.trailList, 2, function(trailList, cb){
						s3.getBucketVersioning({Bucket:trailList.S3BucketName}, function(s3err, s3data){
							if (s3data && s3data.MFADelete && s3data.MFADelete === 'Enabled') {
								pluginInfo.tests.cloudtrailBucketDelete.results.push({
									status: 0,
									message: 'Bucket: ' + trailList.S3BucketName + ' has MFA delete enabled'
								});
							} else {
								pluginInfo.tests.cloudtrailBucketDelete.results.push({
									status: 1,
									message: 'Bucket: ' + trailList.S3BucketName + ' has MFA delete disabled'
								});
							}
							cb();
						});
					}, function(err){
						callback(null, pluginInfo);
					});
				}
			} else {
				pluginInfo.tests.cloudtrailBucketDelete.results.push({
					status: 3,
					message: 'Unable to query for CloudTrail policy'
				});

				return callback(null, pluginInfo);
			}
		});
	}
};