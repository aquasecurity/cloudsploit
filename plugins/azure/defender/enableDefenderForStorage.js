var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender For Storage',
    category: 'Defender',
    domain: 'Management and Governance',
    description: 'Ensures that Microsoft Defender is enabled for Storage.',
    more_info: 'Turning on Microsoft Defender for Storage enables threat detection for Storage, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.',
    recommended_action: 'Enable Microsoft Defender for Storage in Defender plans for the subscription.',
    link: 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction',
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

            let storagePricing = pricings.data.find((pricing) => pricing.name.toLowerCase() === 'storageaccounts');
            if (storagePricing) {
                if (storagePricing.pricingTier.toLowerCase() === 'standard') {
                    helpers.addResult(results, 0, 'Azure Defender is enabled for Storage Accounts', location, storagePricing.id);
                } else {
                    helpers.addResult(results, 2, 'Azure Defender is not enabled for Storage Accounts', location, storagePricing.id);
                }
            } else {
                helpers.addResult(results, 2, 'Azure Defender is not enabled for Storage Accounts', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};