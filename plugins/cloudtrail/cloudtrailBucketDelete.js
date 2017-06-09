var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail Bucket Delete Policy',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token',
	more_info: 'To provide additional security, CloudTrail logging buckets should require an MFA token to delete objects',
	recommended_action: 'Enable MFA delete on the CloudTrail bucket',
	link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete',
	apis: ['CloudTrail:describeTrails', 'S3:getBucketVersioning'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.cloudtrail, function(region, rcb){

			var describeTrails = helpers.addSource(cache, source,
				['cloudtrail', 'describeTrails', region]);

			if (!describeTrails) return rcb();

			if (describeTrails.err || !describeTrails.data) {
				helpers.addResult(results, 3,
					'Unable to query for CloudTrail policy: ' + helpers.addError(describeTrails), region);
				return rcb();
			}

			if (!describeTrails.data.length) {
				helpers.addResult(results, 0, 'No S3 buckets to check', region);
				return rcb();
			}

			async.each(describeTrails.data, function(trail, cb){
				if (!trail.S3BucketName) return cb();

				var getBucketVersioning = helpers.addSource(cache, source,
					['s3', 'getBucketVersioning', 'us-east-1', trail.S3BucketName]);

				if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
					helpers.addResult(results, 3,
						'Error querying for bucket policy for bucket: ' + trail.S3BucketName,
						region, 'arn:aws:s3:::' + trail.S3BucketName)

					return cb();
				}

				if (getBucketVersioning.data.MFADelete &&
					getBucketVersioning.data.MFADelete === 'Enabled') {
					helpers.addResult(results, 0,
						'Bucket: ' + trail.S3BucketName + ' has MFA delete enabled',
						region, 'arn:aws:s3:::' + trail.S3BucketName);
				} else {
					helpers.addResult(results, 1,
						'Bucket: ' + trail.S3BucketName + ' has MFA delete disabled',
						region, 'arn:aws:s3:::' + trail.S3BucketName);
				}

				cb();
			}, function(){
				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};