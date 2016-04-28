var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Certificate Expiry',
	category: 'IAM',
	description: 'Detect upcoming expiration of certificates used with ELBs',
	more_info: 'Certificates that have expired will trigger warnings in all major browsers',
	link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html',
	recommended_action: 'Update your certificates before the expiration date',

	run: function(AWSConfig, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(iam, 'listServerCertificates', function(err, data) {
			if (err || !data || !data.ServerCertificateMetadataList) {
				results.push({
					status: 3,
					message: 'Unable to query for certificates',
					region: 'global'
				});

				return callback(null, results);
			}

			if (!data.ServerCertificateMetadataList.length) {
				results.push({
					status: 0,
					message: 'No certificates found',
					region: 'global'
				});

				return callback(null, results);
			}

			var now = new Date();

			for (i in data.ServerCertificateMetadataList) {
				if (data.ServerCertificateMetadataList[i].ServerCertificateName && data.ServerCertificateMetadataList[i].Expiration) {
					var then = new Date(data.ServerCertificateMetadataList[i].Expiration);
					
					var difference = helpers.functions.daysBetween(then, now);

					if (difference > 45) {
						results.push({
							status: 0,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days',
							region: 'global',
							resource: data.ServerCertificateMetadataList[i].Arn
						});
					} else if (difference > 30) {
						results.push({
							status: 1,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days',
							region: 'global',
							resource: data.ServerCertificateMetadataList[i].Arn
						});
					} else if (difference > 0) {
						results.push({
							status: 2,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days',
							region: 'global',
							resource: data.ServerCertificateMetadataList[i].Arn
						});
					} else {
						results.push({
							status: 2,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expired ' + Math.abs(difference) + ' days ago',
							region: 'global',
							resource: data.ServerCertificateMetadataList[i].Arn
						});
					}
				}
			}

			return callback(null, results);
		});
	}
};