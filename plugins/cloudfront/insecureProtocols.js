var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Insecure CloudFront Protocols',
	category: 'CloudFront',
	description: 'Detects the use of insecure HTTPS SSL/TLS protocols for use with HTTPS traffic between viewers and CloudFront',
	more_info: 'CloudFront supports SSLv3 and TLSv1 protocols for use with HTTPS traffic, but only TLSv1 should be used unless there is a valid business justification to support the older, insecure SSLv3.',
	link: 'http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
	recommended_action: 'Ensure that traffic sent between viewers and CloudFront is passed over HTTPS and uses TLSv1, not SSLv3.',
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
			if (!distribution.ViewerCertificate ||
				!distribution.ViewerCertificate.MinimumProtocolVersion) {
				helpers.addResult(results, 0, 'Distribution is not configured for SSL delivery',
						'global', distribution.ARN);
				return cb();
			}

			// Treat the default certificate as secure
			// IAM/ACM certificates should be analyzed for protocol version
			if (distribution.ViewerCertificate.CloudFrontDefaultCertificate) {
				helpers.addResult(results, 0, 'Distribution is using secure default certificate',
						'global', distribution.ARN);
			} else if (distribution.ViewerCertificate.MinimumProtocolVersion === 'SSLv3') {
				helpers.addResult(results, 1, 'Distribution is using insecure SSLv3',
						'global', distribution.ARN);
			} else {
				helpers.addResult(results, 0, 'Distribution is using secure TLSv1',
						'global', distribution.ARN);
			}

			cb();
		}, function(){
			callback(null, results, source);
		});
	}
};