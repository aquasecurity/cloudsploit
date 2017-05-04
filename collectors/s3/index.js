var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../helpers');

module.exports = function(callKey, forceCloudTrail, AWSConfig, collection, callback) {
	var s3 = new AWS.S3(AWSConfig);

	var knownBuckets = [];

	if (!forceCloudTrail && collection &&
		collection.s3 && collection.s3.listBuckets &&
		collection.s3.listBuckets[AWSConfig.region] &&
		collection.s3.listBuckets[AWSConfig.region].data &&
		collection.s3.listBuckets[AWSConfig.region].data.length) {
		
		knownBuckets = collection.s3.listBuckets[AWSConfig.region].data.map(function(bucket){
			return bucket.Name;
		});
	}

	if (collection && collection.cloudtrail &&
		collection.cloudtrail.describeTrails) {

		for (region in collection.cloudtrail.describeTrails) {
			if (!collection.cloudtrail.describeTrails[region].data ||
				!collection.cloudtrail.describeTrails[region].data.length) continue;

			for (t in collection.cloudtrail.describeTrails[region].data) {
				var trail = collection.cloudtrail.describeTrails[region].data[t];
				
				if (knownBuckets.indexOf(trail.S3BucketName) === -1) {
					knownBuckets.push(trail.S3BucketName);
				}
			}
		}
	}

	if (!knownBuckets || !knownBuckets.length) return callback();

	async.eachLimit(knownBuckets, 10, function(bucket, bcb){
		collection['s3'][callKey][AWSConfig.region][bucket] = {};

		s3[callKey]({Bucket:bucket}, function(bErr, bData){
			if (bErr) {
				collection['s3'][callKey][AWSConfig.region][bucket].err = bErr;

				if (bErr.statusCode && bErr.statusCode == 301) {
					s3.getBucketLocation({Bucket: bucket}, function(locErr, locData){
						if (locErr || !locData || !locData.LocationConstraint) return bcb();
						// Special case where location constraint is EU - rewrite as eu-west-1
						if (locData.LocationConstraint == 'EU') locData.LocationConstraint = 'eu-west-1';
						
						var altAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
						altAWSConfig.region = data.LocationConstraint;
						var s3Alt = new AWS.S3(altAWSConfig);

						s3Alt[callKey]({Bucket:bucket}, function(altErr, altData){
							if (altErr) {
								collection['s3'][callKey][AWSConfig.region][bucket].err = altErr;
							} else {
								collection['s3'][callKey][AWSConfig.region][bucket].err = null;
								collection['s3'][callKey][AWSConfig.region][bucket].data = altData;
							}
							bcb();
						});
					});
				} else {
					bcb();
				}
			} else {
				collection['s3'][callKey][AWSConfig.region][bucket].data = bData;
				bcb();
			}
		});
	}, function(){
		callback();
	});
};