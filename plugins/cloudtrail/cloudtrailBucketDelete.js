// TODO: Enable for all regions

var async = require('async');

var pluginInfo = {
	title: 'CloudTrail Bucket Delete Policy',
	query: 'cloudtrailBucketDelete',
	category: 'CloudTrail',
	aws_service: 'CloudTrail',
	description: 'Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token',
	more_info: 'To provide additional security, CloudTrail logging buckets should require an MFA token to delete objects',
	link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete',
	tests: {
		cloudtrailBucketDelete: {
			title: 'CloudTrail Bucket Delete Policy',
			description: 'Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token',
			recommendedAction: 'Enable MFA delete on the CloudTrail bucket',
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
						status: 0,
						message: 'No S3 buckets to check'
					});
					callback(null, pluginInfo);
				} else {
					var s3 = new AWS.S3();

					async.eachLimit(data.trailList, 2, function(trailList, cb){
						s3.getBucketVersioning({Bucket:trailList.S3BucketName}, function(s3err, s3data){
							if (s3data && s3data.MFADelete && s3data.MFADelete === 'Enabled') {
								pluginInfo.tests.cloudtrailEnabled.results.push({
									status: 0,
									message: 'Bucket: ' + trailList.S3BucketName + ' has MFA delete enabled'
								});
							} else {
								pluginInfo.tests.cloudtrailEnabled.results.push({
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
				callback('unexpected return data');
				return;
			}
		});
	}
};