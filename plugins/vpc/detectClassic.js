// TODO: Finish

var async = require('async');

var pluginInfo = {
	title: 'Detect EC2 Classic',
	query: 'detectClassic',
	category: 'VPC',
	aws_service: 'VPC',
	description: 'Ensures AWS VPC is being used instead of EC2 Classic',
	more_info: 'VPCs are the latest and more secure method of launching AWS resources. EC2 Classic should not be used.',
	link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html',
	tests: {
		detectClassic: {
			title: 'Detect EC2 Classic',
			description: 'Ensures AWS VPC is being used instead of EC2 Classic',
			recommendedAction: 'Migrate resources from EC2 Classic to VPC',
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
		var ec2 = new AWS.EC2();

		ec2.xxx({}, function(err, data){
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