var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Public S3 CloudFront Origin',
	category: 'CloudFront',
	description: 'Detects the use of an S3 bucket as a CloudFront origin without an origin access identity',
	more_info: 'When S3 is used as an origin for a CloudFront bucket, the contents should be kept private and an origin access identity should allow CloudFront access. This prevents someone from bypassing the caching benefits that CloudFront provides, repeatedly loading objects directly from S3, and amassing a large access bill.',
	link: 'http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html',
	recommended_action: 'Create an origin access identity for CloudFront, then make the contents of the S3 bucket private.',

	run: function(AWSConfig, cache, callback) {

		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var cloudfront = new AWS.CloudFront(LocalAWSConfig);

		helpers.cache(cache, cloudfront, 'listDistributions', function(err, data) {
			if (err || !data || !data.DistributionList) {
				results.push({
					status: 3,
					message: 'Unable to query for CloudFront distributions',
					region: 'global'
				});

				return callback(null, results);
			}

			if (!data.DistributionList.Items || !data.DistributionList.Items.length) {
				results.push({
					status: 0,
					message: 'No CloudFront distributions found',
					region: 'global'
				});

				return callback(null, results);
			}

			async.each(data.DistributionList.Items, function(distribution, cb){
				if (!distribution.Origins || !distribution.Origins.Items || !distribution.Origins.Items.length) {
					results.push({
						status: 0,
						message: 'No CloudFront distributions found',
						resource: distribution.DomainName,
						region: 'global'
					});

					return cb();
				}

				for (o in distribution.Origins.Items) {
					var origin = distribution.Origins.Items[o];

					if (origin.S3OriginConfig && (!origin.S3OriginConfig.OriginAccessIdentity || !origin.S3OriginConfig.OriginAccessIdentity.length)) {
						results.push({
							status: 2,
							message: 'CloudFront distribution is using an S3 origin without an origin access identity',
							resource: distribution.DomainName,
							region: 'global'
						});

						return cb();
					}

					results.push({
						status: 0,
						message: 'CloudFront distribution is not using any S3 origins without an origin access identity',
						resource: distribution.DomainName,
						region: 'global'
					});
				}

				cb();

			}, function(){
				callback(null, results);
			});
		});
	}
};