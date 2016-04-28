var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Domain Transfer Lock',
	category: 'Route53',
	description: 'Ensures domains have the transfer lock set',
	more_info: 'To avoid having a domain maliciously transferred to a third-party, all domains should enable the transfer lock unless actively being tranferred.',
	link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html',
	recommended_action: 'Enable the transfer lock for the domain',

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

				if (data.Domains[i].TransferLock) {
					results.push({
						status: 0,
						message: 'Domain: ' + data.Domains[i].DomainName + ' has the transfer lock enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				} else {
					results.push({
						status: 2,
						message: 'Domain: ' + data.Domains[i].DomainName + ' does not have the transfer lock enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				}
			}

			callback(null, results);
		});
	}
};
