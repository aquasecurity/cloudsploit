var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Public S3 CloudFront Origin',
	category: 'CloudFront',
	description: 'Detects the use of an S3 bucket as a CloudFront origin without an origin access identity',
	more_info: 'When S3 is used as an origin for a CloudFront bucket, the contents should be kept private and an origin access identity should allow CloudFront access. This prevents someone from bypassing the caching benefits that CloudFront provides, repeatedly loading objects directly from S3, and amassing a large access bill.',
	link: 'http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html',
	recommended_action: 'Create an origin access identity for CloudFront, then make the contents of the S3 bucket private.',
	apis: ['CloudFront:listDistributions'],

	run: function(cache, callback) {

		var results = [];
		var source = {};

		var listDistributions = helpers.addSource(cache, source,
			['cloudfront', 'listDistributions', 'us-east-1']);

		if (!listDistributions) return callback(null, results, source);

		if (listDistributions.err || !listDistributions.data) {
			helpers.addResult(results, 3,
				'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
			return callback(null, results, source);
		}

		if (!listDistributions.data.length) {
			helpers.addResult(results, 0, 'No CloudFront distributions found');
		}

		async.each(listDistributions.data, function(distribution, cb){
			if (!distribution.Origins ||
				!distribution.Origins.Items ||
				!distribution.Origins.Items.length) {
				helpers.addResult(results, 0, 'No CloudFront origins found',
						'global', distribution.ARN);
				return cb();
			}

			for (o in distribution.Origins.Items) {
				var origin = distribution.Origins.Items[o];

				if (origin.S3OriginConfig &&
					(!origin.S3OriginConfig.OriginAccessIdentity ||
					 !origin.S3OriginConfig.OriginAccessIdentity.length)) {
					helpers.addResult(results, 2, 'CloudFront distribution is using an S3 ' + 
						'origin without an origin access identity', 'global',
						distribution.ARN);
				} else {
					helpers.addResult(results, 0, 'CloudFront distribution origin is not setup ' +
							'without an origin access identity', 'global',
							distribution.ARN);
				}
			}

			cb();

		}, function(){
			callback(null, results, source);
		});
	}
};