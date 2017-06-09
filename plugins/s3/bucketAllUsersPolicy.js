var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'S3 Bucket All Users Policy',
	category: 'S3',
	description: 'Ensures S3 buckets do not allow global write, delete, or read ACL permissions',
	more_info: 'S3 buckets can be configured to allow anyone, regardless of whether they are an AWS user or not, to write objects to a bucket or delete objects. This option should not be configured unless their is a strong business requirement.',
	recommended_action: 'Disable global all users policies on all S3 buckets',
	link: 'http://docs.aws.amazon.com/AmazonS3/latest/UG/EditingBucketPermissions.html',
	apis: ['S3:listBuckets', 'S3:getBucketAcl'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var listBuckets = helpers.addSource(cache, source,
			['s3', 'listBuckets', region]);

		if (!listBuckets) return callback(null, results, source);

		if (listBuckets.err || !listBuckets.data) {
			helpers.addResult(results, 3,
				'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
			return callback(null, results, source);
		}

		if (!listBuckets.data.length) {
			helpers.addResult(results, 0, 'No S3 buckets to check');
			return callback(null, results, source);
		}

		for (i in listBuckets.data) {
			var bucket = listBuckets.data[i];
			if (!bucket.Name) continue;

			var bucketResource = 'arn:aws:s3:::' + bucket.Name;

			var getBucketAcl = helpers.addSource(cache, source,
				['s3', 'getBucketAcl', region, bucket.Name]);

			if (!getBucketAcl || getBucketAcl.err || !getBucketAcl.data) {
				helpers.addResult(results, 3,
					'Error querying for bucket policy for bucket: ' + bucket.Name,
					'global', bucketResource);
				continue;
			}

			var allowsAllUsersTypes = [];

			for (g in getBucketAcl.data.Grants) {
				var grant = getBucketAcl.data.Grants[g];

				if (grant.Grantee &&
					grant.Grantee.Type &&
					grant.Grantee.Type === 'Group' &&
					grant.Grantee.URI &&
					grant.Grantee.URI.indexOf('AllUsers') > -1 &&
					grant.Permission &&
					grant.Permission !== 'READ'
				) {
					allowsAllUsersTypes.push(grant.Permission);
				}
			}

			if (allowsAllUsersTypes.length) {
				helpers.addResult(results, 2,
					'Bucket: ' + bucket.Name + ' allows global access to: ' + allowsAllUsersTypes.concat(', '),
					'global', bucketResource);
			} else {
				helpers.addResult(results, 0,
					'Bucket: ' + bucket.Name + ' does not allow global write or read ACL access',
					'global', bucketResource);
			}
		}
		
		callback(null, results, source);
	}
};