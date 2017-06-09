var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Certificate Expiry',
	category: 'IAM',
	description: 'Detect upcoming expiration of certificates used with ELBs',
	more_info: 'Certificates that have expired will trigger warnings in all major browsers',
	link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html',
	recommended_action: 'Update your certificates before the expiration date',
	apis: ['IAM:listServerCertificates'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var listServerCertificates = helpers.addSource(cache, source,
				['iam', 'listServerCertificates', region]);

		if (!listServerCertificates) return callback(null, results, source);

		if (listServerCertificates.err || !listServerCertificates.data) {
			helpers.addResult(results, 3,
				'Unable to query for certificates: ' + helpers.addError(listServerCertificates));
			return callback(null, results, source);
		}

		if (!listServerCertificates.data.length) {
			helpers.addResult(results, 0, 'No certificates found');
			return callback(null, results, source);
		}

		var now = new Date();

		for (i in listServerCertificates.data) {
			if (listServerCertificates.data[i].ServerCertificateName && listServerCertificates.data[i].Expiration) {
				var certificate = listServerCertificates.data[i];

				var then = new Date(certificate.Expiration);
				
				var difference = helpers.functions.daysBetween(then, now);
				var expiresInMsg = 'Certificate: ' + certificate.ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days';
				var expiredMsg = 'Certificate: ' + certificate.ServerCertificateName + ' expired ' + Math.abs(difference) + ' days ago';

				// Expired already
				if (then < now) {
					helpers.addResult(results, 2, expiredMsg, 'global', certificate.Arn);
				} else {
					// Expires in the future
					if (difference > 45) {
						helpers.addResult(results, 0, expiresInMsg, 'global', certificate.Arn);
					} else if (difference > 30) {
						helpers.addResult(results, 1, expiresInMsg, 'global', certificate.Arn);
					} else if (difference > 0) {
						helpers.addResult(results, 2, expiresInMsg, 'global', certificate.Arn);
					} else {
						helpers.addResult(results, 0, expiredMsg, 'global', certificate.Arn);
					}
				}
			}
		}

		callback(null, results, source);
	}
};