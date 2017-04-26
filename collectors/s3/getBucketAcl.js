var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
	var s3 = new AWS.S3(AWSConfig);

	var knownBuckets;
	var filter;

	if (collection && collection.s3 && collection.s3.listBuckets &&
		collection.s3.listBuckets[AWSConfig.region] &&
		collection.s3.listBuckets[AWSConfig.region].data &&
		collection.s3.listBuckets[AWSConfig.region].data.length) {
		knownBuckets = collection.s3.listBuckets[AWSConfig.region].data;
		filter = 'Name';
	} else if (collection && collection.cloudtrail &&
		collection.cloudtrail.describeTrails &&
		collection.cloudtrail.describeTrails[AWSConfig.region] &&
		collection.cloudtrail.describeTrails[AWSConfig.region].data &&
		collection.cloudtrail.describeTrails[AWSConfig.region].data.length) {
		knownBuckets = collection.cloudtrail.describeTrails[AWSConfig.region].data;
		filter = 'S3BucketName';
	}

	if (!knownBuckets) return callback();

	async.eachLimit(knownBuckets, 10, function(bucket, bcb){
		if (!bucket[filter]) return bcb();

		collection['s3']['getBucketAcl'][AWSConfig.region][bucket[filter]] = {};

		s3.getBucketAcl({Bucket:bucket[filter]}, function(bErr, bData){
			if (bErr) {
				collection['s3']['getBucketAcl'][AWSConfig.region][bucket[filter]].err = bErr;

				if (bErr.statusCode && bErr.statusCode == 301) {
					s3.getBucketLocation({Bucket: bucket[filter]}, function(locErr, locData){
						if (locErr || !locData || !locData.LocationConstraint) return bcb();
						// Special case where location constraint is EU - rewrite as eu-west-1
						if (locData.LocationConstraint == 'EU') locData.LocationConstraint = 'eu-west-1';
						
						var altAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
						altAWSConfig.region = data.LocationConstraint;
						var s3Alt = new AWS.S3(altAWSConfig);

						s3Alt.getBucketAcl({Bucket:bucket[filter]}, function(altErr, altData){
							if (altErr || !altData) return bcb();
							collection['s3']['getBucketAcl'][AWSConfig.region][bucket[filter]].err = null;
							collection['s3']['getBucketAcl'][AWSConfig.region][bucket[filter]].data = altData;
							bcb();
						});
					});
				}
			} else {
				collection['s3']['getBucketAcl'][AWSConfig.region][bucket[filter]].data = bData;
				bcb();
			}
		});
	}, function(){
		callback();
	});
};