var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Domain Transfer Lock',
    category: 'Route53',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures domains have the transfer lock set',
    more_info: 'To avoid having a domain maliciously transferred to a third-party, all domains should enable the transfer lock unless actively being transferred.',
    link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html',
    recommended_action: 'Enable the transfer lock for the domain',
    apis: ['Route53Domains:listDomains'],
    realtime_triggers: ['route53domains:RegisterDomain', 'route53domain:EnableDomainTransferLock', 'route53domain:DisableDomainTransferLock','route53domians:DeleteDomain'],

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


        var dtlUnsupportedDomains= [
            '.za',
            '.cl',
            '.ar',
            '.au',
            '.nz',
            '.au',
            '.jp',
            '.qa',
            '.ru',
            '.ch',
            '.de',
            '.es',
            '.eu',
            'fi',
            '.it',
            '.nl',
            '.se',
        ];
        var unsupported = false;

        for (var i in listDomains.data) {
            var domain = listDomains.data[i];

            if (!domain.DomainName) continue;

            dtlUnsupportedDomains.forEach((region) => {
                if (domain.DomainName.includes(region)) {
                    unsupported = true;
                }
            });
            // Skip the unsupported domains
            if (unsupported) {
                helpers.addResult(results, 0,
                    'Domain: ' + domain.DomainName + ' does not support transfer locks',
                    'global', domain.DomainName);
            } else if (domain.TransferLock) {
                helpers.addResult(results, 0,
                    'Domain: ' + domain.DomainName + ' has the transfer lock enabled',
                    'global', domain.DomainName);
            } else {
                helpers.addResult(results, 2,
                    'Domain: ' + domain.DomainName + ' does not have the transfer lock enabled',
                    'global', domain.DomainName);
            }
        }

        callback(null, results, source);
    }
};
