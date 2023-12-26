var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender For PostgreSQL Flexible Servers',
    category: 'Defender',
    domain: 'Management and Governance',
    description: 'Ensures that Microsoft Defender is enabled for Azure PostgreSQL Flexible Servers.',
    more_info: 'Enabling Defender for Cloud on PostgreSQL Flexible Servers allows detection of unusual database access, query patterns, and suspicious activities, enhancing overall security.',
    recommended_action: 'Enable Microsoft Defender for PostgreSQL Flexible Servers in Defender plans for the subscription.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-security#microsoft-defender-for-cloud-support',
    apis: ['pricings:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.pricings, function(location, rcb) {
            var pricings = helpers.addSource(cache, source,
                ['pricings', 'list', location]);

            if (!pricings) return rcb();

            if (pricings.err || !pricings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Pricing: ' + helpers.addError(pricings), location);
                return rcb();
            }

            if (!pricings.data.length) {
                helpers.addResult(results, 0, 'No Pricing information found', location);
                return rcb();
            }

            let postgresqlServersPricing = pricings.data.find((pricing) => pricing.name && pricing.name.toLowerCase() === 'opensourcerelationaldatabases');
            
            if (postgresqlServersPricing) {
                if (postgresqlServersPricing.pricingTier.toLowerCase() === 'standard') {
                    helpers.addResult(results, 0, 'Azure Defender is enabled for PostgreSQL Flexible Servers', location, postgresqlServersPricing.id);
                } else {
                    helpers.addResult(results, 2, 'Azure Defender is not enabled for PostgreSQL Flexible Servers', location, postgresqlServersPricing.id);
                }
            } else {
                helpers.addResult(results, 2, 'Azure Defender is not enabled for PostgreSQL Flexible Servers', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};