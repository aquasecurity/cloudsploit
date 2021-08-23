var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Domain Privacy Protection',
    category: 'Route53',
    description: 'Ensure that Privacy Protection feature is enabled for your Amazon Route 53 domains.',
    more_info: 'Enabling the Privacy Protection feature protects against receiving spams and sharing contact information in response of WHOIS queries.',
    link: 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-privacy-protection.html',
    recommended_action: 'Enable Privacy Protection for Domain',
    apis: ['Route53Domains:listDomains', 'Route53Domains:getDomainDetail'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

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

        listDomains.data.forEach(domain => {
            if (!domain.DomainName) return;

            var domainDetail = helpers.addSource(cache, source,
                ['route53domains', 'getDomainDetail', region, domain.DomainName]);

            if (!domainDetail || domainDetail.err || !domainDetail.data) {
                helpers.addResult(results, 3,
                    'Unable to query for domain details: ' + helpers.addError(domainDetail));
                return;
            }

            const status = domainDetail.data.RegistrantPrivacy ? 0 : 2;
            helpers.addResult(results, status,
                'Domain: ' + domain.DomainName + ` ${status == 0 ? 'has': 'does not have'} privacy protection enabled`,
                'global', domain.DomainName);

        });

        callback(null, results, source);
    }
};
