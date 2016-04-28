var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Domain Auto Renew',
	category: 'Route53',
	description: 'Ensures domains are set to auto renew through Route53',
	more_info: 'Domains purchased through Route53 should be set to auto renew. Domains that are not renewed can quickly be acquired by a third-party and cause loss of access for customers.',
	link: 'http://docs.aws.amazon.com/Route53/latest/APIReference/api-enable-domain-auto-renew.html',
	recommended_action: 'Enable auto renew for the domain',

	run: function(AWSConfig, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var route53domains = new AWS.Route53Domains(LocalAWSConfig);

		helpers.cache(route53domains, 'listDomains', function(err, data) {
			if (err || !data || !data.Domains) {
				results.push({
					status: 3,
					message: 'Unable to query for domains',
					region: 'global'
				});

				return callback(null, results);
			}

			if (!data.Domains.length) {
				results.push({
					status: 0,
					message: 'No domains registered through Route53',
					region: 'global'
				});

				return callback(null, results);
			}

			for (i in data.Domains) {

				if (data.Domains[i].AutoRenew) {
					results.push({
						status: 0,
						message: 'Domain: ' + data.Domains[i].DomainName + ' has auto renew enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				} else {
					results.push({
						status: 1,
						message: 'Domain: ' + data.Domains[i].DomainName + ' does not have auto renew enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				}
			}

			callback(null, results);
		});
	}
};
