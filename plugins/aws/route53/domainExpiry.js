var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Domain Expiry',
    category: 'Route53',
    domain: 'Content Delivery',
    description: 'Ensures domains are not expiring too soon',
    more_info: 'Expired domains can be lost and reregistered by a third-party.',
    link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html',
    recommended_action: 'Reregister the expiring domain',
    apis: ['Route53Domains:listDomains'],

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

        for (var domain of listDomains.data) {
            if (domain.Expiry) {
                var difference = Math.round((new Date(domain.Expiry).getTime() - new Date().getTime())/(24*60*60*1000));
                var returnMsg = 'Domain: ' + domain.DomainName + ' expires in ' + difference + ' days';

                if (difference > 35) {
                    helpers.addResult(results, 0, returnMsg, 'global', domain.DomainName);
                } else if (domain.DomainName.endsWith(('.com.ar, .com.br, .jp')) && difference > 30) {
                    helpers.addResult(results, 0, returnMsg, 'global', domain.DomainName);
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
