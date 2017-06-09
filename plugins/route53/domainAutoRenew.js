var helpers = require('../../helpers');

module.exports = {
	title: 'Domain Auto Renew',
	category: 'Route53',
	description: 'Ensures domains are set to auto renew through Route53',
	more_info: 'Domains purchased through Route53 should be set to auto renew. Domains that are not renewed can quickly be acquired by a third-party and cause loss of access for customers.',
	link: 'http://docs.aws.amazon.com/Route53/latest/APIReference/api-enable-domain-auto-renew.html',
	recommended_action: 'Enable auto renew for the domain',
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

			if (domain.AutoRenew) {
				helpers.addResult(results, 0,
					'Domain: ' + domain.DomainName + ' has auto renew enabled',
					'global', domain.DomainName);
			} else {
				helpers.addResult(results, 1,
					'Domain: ' + domain.DomainName + ' does not have auto renew enabled',
					'global', domain.DomainName);
			}
		}

		callback(null, results, source);
	}
};
