var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Secure CloudFront Origin',
	category: 'CloudFront',
	description: 'Detects the use of secure web origins with secure protocols for CloudFront.',
	more_info: 'Traffic passed between the CloudFront edge nodes and the backend resource should be sent over HTTPS with modern protocols for all web-based origins.',
	link: 'http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web.html',
	recommended_action: 'Ensure that traffic sent between CloudFront and its origin is passed over HTTPS and uses TLSv1.1 or higher. Do not use the match-viewer option.',
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

		var found = false;

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

				if (origin.CustomOriginConfig &&
					origin.CustomOriginConfig.OriginProtocolPolicy &&
					origin.CustomOriginConfig.OriginProtocolPolicy) {

					found = true;

					var checkProtocols = false;

					if (origin.CustomOriginConfig.OriginProtocolPolicy === 'https-only') {
						checkProtocols = true;
						helpers.addResult(results, 0,
							'CloudFront origin: ' + origin.Id + ' is using https-only', 'global',
							distribution.ARN);
					} else if (origin.CustomOriginConfig.OriginProtocolPolicy === 'match-viewer') {
						checkProtocols = true;
						helpers.addResult(results, 1,
							'CloudFront origin: ' + origin.Id + ' is using match-viewer', 'global',
							distribution.ARN);
					} else if (origin.CustomOriginConfig.OriginProtocolPolicy === 'http-only') {
						helpers.addResult(results, 2,
							'CloudFront origin: ' + origin.Id + ' is using http-only', 'global',
							distribution.ARN);
					}

					if (checkProtocols &&
						origin.CustomOriginConfig.OriginSslProtocols &&
						origin.CustomOriginConfig.OriginSslProtocols.Items &&
						origin.CustomOriginConfig.OriginSslProtocols.Items.length) {
						var protocols = origin.CustomOriginConfig.OriginSslProtocols.Items;

						if (protocols.indexOf('SSLv3') > -1 && protocols.indexOf('TLSv1') > -1) {
							helpers.addResult(results, 2,
								'CloudFront origin: ' + origin.Id + ' is using SSLv3 and TLSv1 protocols', 'global',
								distribution.ARN);
						} else if (protocols.indexOf('SSLv3') > -1) {
							helpers.addResult(results, 2,
								'CloudFront origin: ' + origin.Id + ' is using SSLv3 protocol', 'global',
								distribution.ARN);
						} else if (protocols.indexOf('TLSv1') > -1) {
							helpers.addResult(results, 1,
								'CloudFront origin: ' + origin.Id + ' is using TLSv1 protocol', 'global',
								distribution.ARN);
						}
					}
				}
			}

			cb();
		}, function(){
			if (!found) {
				helpers.addResult(results, 0, 'No CloudFront origins without HTTPS or with insecure protocols found');
			}

			callback(null, results, source);
		});
	}
};