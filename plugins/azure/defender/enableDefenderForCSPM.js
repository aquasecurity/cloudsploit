var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender For CSPM',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensures that Microsoft Defender is enabled for CSPM.',
    more_info: 'Turning on Microsoft Defender for CSPM enables threat detection, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.',
    recommended_action: 'Enable Microsoft Defender for CSPM in Defender plans for the subscription.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management',
    apis: ['pricings:list'],
    realtime_triggers: ['microsoftsecurity:pricings:write','microsoftsecurity:pricings:delete'],

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

            helpers.checkMicrosoftDefender(pricings, 'cloudposture', 'CSPM', results, location);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};