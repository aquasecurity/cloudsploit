var helpers = require('../../helpers');

module.exports = {
	title: 'Domain Expiry',
	category: 'Route53',
	description: 'Ensures domains are not expiring too soon',
	more_info: 'Expired domains can be lost and reregistered by a third-party.',
	link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html',
	recommended_action: 'Reregister the expiring domain',
	apis: ['Route53Domains:listDomains'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var listDomains = helpers.addSource(cache, source,
			['route53domains', 'listDomains', region]);

		if (!listDomains) return callback(null, results, source);

		if (listDomains.err || !listDomains.data) {
			helpers.addResult(results, 3,
				'Unable to query for domains: ' + helpers.addError(listDomains));
			return callback(null, results, source);
		}

		if (!listDomains.data.length) {
			helpers.addResult(results, 0, 'No domains registered through Route53');
			return callback(null, results, source);
		}

		for (i in listDomains.data) {
			var domain = listDomains.data[i];

			if (domain.Expiry) {
				var difference = helpers.functions.daysAgo(domain.Expiry);
				var returnMsg = 'Domain: ' + domain.DomainName + ' expires in ' + difference + ' days';

				if (difference > 45) {
					helpers.addResult(results, 0, returnMsg, 'global', domain.DomainName);
				} else if (difference > 30) {
					helpers.addResult(results, 1, returnMsg, 'global', domain.DomainName);
				} else if (difference > 0) {
					helpers.addResult(results, 2, returnMsg, 'global', domain.DomainName);
				} else {
					helpers.addResult(results, 2,
						'Domain: ' + domain.DomainName + ' expired ' + difference + ' days ago',
						'global', domain.DomainName);
				}
			} else {
				helpers.addResult(results, 3,
					'Expiration for domain: ' + domain.DomainName + ' could not be determined',
					'global', domain.DomainName);
			}
		}

		callback(null, results, source);
	}
};
