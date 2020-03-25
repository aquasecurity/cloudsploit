var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Standard Pricing Enabled',
    category: 'Security Center',
    description: 'Ensures that standard pricing is enabled in the security center',
    more_info: 'Enabling standard pricing increases the security posture of the subscription. This enables advanced security monitoring for the services covered under the security center.',
    recommended_action: 'Ensure that standard pricing is enabled in the security center.',
    link: 'https://azure.microsoft.com/en-us/pricing/details/security-center/',
    apis: ['pricings:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.pricings, function(location, rcb){
            var pricings = helpers.addSource(cache, source,
                ['pricings', 'list', location]);

            if (!pricings) return rcb();

            if (pricings.err || !pricings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security center pricing: ' + helpers.addError(pricings), location);
                return rcb();
            }

            if (!pricings.data.length) {
                helpers.addResult(results, 0, 'No security center pricings found', location);
                return rcb();
            }

            pricings.data.forEach(pricing => {
                if (pricing.pricingTier &&
                    pricing.pricingTier === 'Standard') {
                    helpers.addResult(results, 0, 'Standard pricing is enabled for the service', location, pricing.id);
                } else {
                    helpers.addResult(results, 2, 'Standard pricing is not enabled for the service', location, pricing.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
