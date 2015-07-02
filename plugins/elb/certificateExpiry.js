var AWS = require('aws-sdk');
var async = require('async');

function getPluginInfo() {
	return {
		title: 'Certificate Expiry',
		query: 'certificateExpiry',
		category: 'ELB',
		aws_service: 'ELB',
		description: 'Detect upcoming expiration of certificates used with ELBs',
		more_info: 'Certificates that have expired will trigger warnings in all major browsers',
		link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html',
		tests: {
			certificateExpiry: {
				title: 'Certificate Expiry',
				description: 'Detect upcoming expiration of certificates used with ELBs',
				recommendedAction: 'Update your certificates before the expiration date',
				results: []
			}
		}
	}
};

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,

	run: function(AWSConfig, callback) {
		var iam = new AWS.IAM(AWSConfig);
		var pluginInfo = getPluginInfo();

		iam.listServerCertificates({MaxItems:100}, function(err, data){
			if (err || !data || !data.ServerCertificateMetadataList) {
				pluginInfo.tests.certificateExpiry.results.push({
					status: 3,
					message: 'Unable to query for certificates'
				});

				return callback(null, pluginInfo);
			}

			if (!data.ServerCertificateMetadataList.length) {
				pluginInfo.tests.certificateExpiry.results.push({
					status: 0,
					message: 'No certificates found'
				});

				return callback(null, pluginInfo);
			}

			var now = new Date();

			if (data.ServerCertificateMetadataList.length > 100) {
				pluginInfo.tests.certificateExpiry.results.push({
					status: 3,
					message: 'More than 100 certificates were found. Certificates beyond 100 were not tested'
				});
			}

			for (i in data.ServerCertificateMetadataList) {
				if (data.ServerCertificateMetadataList[i].ServerCertificateName && data.ServerCertificateMetadataList[i].Expiration) {
					var then = new Date(data.ServerCertificateMetadataList[i].Expiration);
					var difference = Math.floor((then - now) / 1000 / 60 / 60 / 24);	// number of days difference

					if (difference > 45) {
						pluginInfo.tests.certificateExpiry.results.push({
							status: 0,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days'
						});
					} else if (difference > 30) {
						pluginInfo.tests.certificateExpiry.results.push({
							status: 1,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days'
						});
					} else if (difference > 0) {
						pluginInfo.tests.certificateExpiry.results.push({
							status: 2,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days'
						});
					} else {
						pluginInfo.tests.certificateExpiry.results.push({
							status: 2,
							message: 'Certificate: ' + data.ServerCertificateMetadataList[i].ServerCertificateName + ' expired ' + Math.abs(difference) + ' days ago'
						});
					}
				}
			}

			return callback(null, pluginInfo);
		});
	}
};