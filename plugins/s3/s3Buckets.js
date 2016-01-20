var async = require('async');
var AWS = require('aws-sdk');
var regions = require(__dirname + '/../../regions.json');

function getPluginInfo() {
	return {
		title: 'S3 Buckets',
		query: 's3Buckets',
		category: 'S3',
		description: 'Ensures S3 buckets use proper policies and access controls',
		tests: {
			bucketAllUsersPolicy: {
				title: 'S3 Bucket All Users Policy',
				description: 'Ensures S3 buckets do not allow global write, delete, or read ACL permissions',
				more_info: 'S3 buckets can be configured to allow anyone, regardless of whether they are an AWS user or not, to write objects to a bucket or delete objects. This option should not be configured unless their is a strong business requirement.',
				recommended_action: 'Disable global all users policies on all S3 buckets',
				link: 'http://docs.aws.amazon.com/AmazonS3/latest/UG/EditingBucketPermissions.html',
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
		var pluginInfo = getPluginInfo();

		// Buckets are a global service and will fail if a region is specified
		if (AWSConfig.region) {
			delete AWSConfig.region;
		}

		var s3 = new AWS.S3(AWSConfig);

		s3.listBuckets(function(err, data){
			if (err) {
				pluginInfo.tests.bucketAllUsersPolicy.results.push({
					status: 3,
					message: 'Unable to query for S3 buckets',
					region: 'global'
				});

				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if delete policy is set
			if (data && data.Buckets) {
				if (!data.Buckets.length) {
					pluginInfo.tests.bucketAllUsersPolicy.results.push({
						status: 0,
						message: 'No S3 buckets to check',
						region: 'global'
					});
					return callback(null, pluginInfo);
				}

				async.eachLimit(data.Buckets, 20, function(bucket, cb){
					s3.getBucketAcl({Bucket:bucket.Name}, function(err, data){
						if (err || !data) {
							pluginInfo.tests.bucketAllUsersPolicy.results.push({
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
							pluginInfo.tests.bucketAllUsersPolicy.results.push({
								status: 2,
								message: 'Bucket: ' + bucket.Name + ' allows global access to: ' + allowsAllUsersTypes.concat(', '),
								region: 'global',
								resource: 'arn:aws:s3:::' + bucket.Name
							});
						} else {
							pluginInfo.tests.bucketAllUsersPolicy.results.push({
								status: 0,
								message: 'Bucket: ' + bucket.Name + ' does not allow global write or read ACL access',
								region: 'global',
								resource: 'arn:aws:s3:::' + bucket.Name
							});
						}
						cb();
					});
				}, function(){
					return callback(null, pluginInfo);
				});
			} else {
				pluginInfo.tests.bucketAllUsersPolicy.results.push({
					status: 3,
					message: 'Unknown response for S3 bucket query',
					region: 'global'
				});

				return callback(null, pluginInfo);
			}
		});
	}
};