var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Route 53 In Use',
    category: 'Route53',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensure that AWS Route 53 Domain Name System (DNS) service is used within your AWS account.',
    more_info: 'AWS Route 53 allows you to create and manage DNS hosted zones for all your domain names registered with AWS or with other domain registrars.',
    link: 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html',
    recommended_action: 'Register your domain using Route53 DNS service.',
    apis: ['Route53:listHostedZones'],
    realtime_triggers: ['route53:CreateHostedZone','route53:DeleteHostedZone'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);
        var listHostedZones = helpers.addSource(cache, source,
            ['route53', 'listHostedZones', region]);

        if (!listHostedZones) return callback(null, results, source);
        
        if (listHostedZones.err || !listHostedZones.data) {
            helpers.addResult(results, 3,
                `Unable to query for hosted zones: ${helpers.addError(listHostedZones)}`,
                region);
            return callback(null, results, source);
        }

        
        if (!listHostedZones.data.length) {
            helpers.addResult(results, 2, 'Route53 DNS service is not in use', region);
        } else {
            helpers.addResult(results, 0, 'Route53 DNS service is in use', region);
        }

        return callback(null, results, source);
    }
};
