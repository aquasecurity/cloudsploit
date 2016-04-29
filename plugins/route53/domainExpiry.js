var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Domain Expiry',
	category: 'Route53',
	description: 'Ensures domains are not expiring too soon',
	more_info: 'Expired domains can be lost and reregistered by a third-party.',
	link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html',
	recommended_action: 'Reregister the expiring domain',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var route53domains = new AWS.Route53Domains(LocalAWSConfig);

		helpers.cache(cache, route53domains, 'listDomains', function(err, data) {
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

				if (data.Domains[i].Expiry) {
					var difference = helpers.functions.daysAgo(data.Domains[i].Expiry);

					if (difference > 45) {
						results.push({
							status: 0,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expires in ' + difference + ' days',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					} else if (difference > 30) {
						results.push({
							status: 1,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expires in ' + difference + ' days',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					} else if (difference > 0) {
						results.push({
							status: 2,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expires in ' + difference + ' days',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					} else {
						results.push({
							status: 2,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expired ' + difference + ' days ago',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					}
				} else {
					results.push({
						status: 3,
						message: 'Expiration for domain: ' + data.Domains[i].DomainName + ' could not be determined',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				}
			}

			callback(null, results);
		});
	}
};
