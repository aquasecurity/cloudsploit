var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'S3 Bucket All Users Policy',
	category: 'S3',
	description: 'Ensures S3 buckets do not allow global write, delete, or read ACL permissions',
	more_info: 'S3 buckets can be configured to allow anyone, regardless of whether they are an AWS user or not, to write objects to a bucket or delete objects. This option should not be configured unless their is a strong business requirement.',
	recommended_action: 'Disable global all users policies on all S3 buckets',
	link: 'http://docs.aws.amazon.com/AmazonS3/latest/UG/EditingBucketPermissions.html',

	run: function(AWSConfig, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var s3 = new AWS.S3(LocalAWSConfig);

		helpers.cache(s3, 'listBuckets', function(err, data) {
			if (err || !data || !data.Buckets) {
				results.push({
					status: 3,
					message: 'Unable to query for S3 buckets',
					region: 'global'
				});

				return callback(null, results);
			}

			if (!data.Buckets.length) {
				results.push({
					status: 0,
					message: 'No S3 buckets to check',
					region: 'global'
				});
				return callback(null, results);
			}

			async.eachLimit(data.Buckets, 20, function(bucket, cb){
				s3.getBucketAcl({Bucket:bucket.Name}, function(err, data){
					if (err || !data) {
						results.push({
							status: 3,
							message: 'Error querying for bucket policy for bucket: ' + bucket.Name,
							region: 'global',
							resource: 'arn:aws:s3:::' + bucket.Name
						});

						return cb();
					}

					var allowsAllUsersTypes = [];

					for (i in data.Grants) {
						if (data.Grants[i].Grantee.Type &&
							data.Grants[i].Grantee.Type === 'Group' &&
							data.Grants[i].Grantee.URI &&
							data.Grants[i].Grantee.URI.indexOf('AllUsers') > -1 &&
							data.Grants[i].Permission &&
							data.Grants[i].Permission !== 'READ'
						) {
							allowsAllUsersTypes.push(data.Grants[i].Permission);
						}
					}

					if (allowsAllUsersTypes.length) {
						results.push({
							status: 2,
							message: 'Bucket: ' + bucket.Name + ' allows global access to: ' + allowsAllUsersTypes.concat(', '),
							region: 'global',
							resource: 'arn:aws:s3:::' + bucket.Name
						});
					} else {
						results.push({
							status: 0,
							message: 'Bucket: ' + bucket.Name + ' does not allow global write or read ACL access',
							region: 'global',
							resource: 'arn:aws:s3:::' + bucket.Name
						});
					}
					cb();
				});
			}, function(){
				callback(null, results);
			});
		});
	}
};