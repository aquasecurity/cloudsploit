var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender Endpoint Integration',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Microsoft Defender for Endpoint integration is enabled.',
    more_info: 'Window Defender ATP integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration helps to spot abnormalities, detect and respond to advanced attacks on Windows server endpoints monitored by Microsoft Defender for Cloud.',
    recommended_action: 'Enable "Allow Microsoft Defender for Endpoint to access my data setting" in Defender environment settings.',
    link: 'https://learn.microsoft.com/en-in/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows',
    apis: ['securityCenter:list'],
    realtime_triggers: ['microsoftsecurity:pricings:write','microsoftsecurity:pricings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.securityCenter, function(location, rcb) {
            var defenderSettings = helpers.addSource(cache, source,
                ['securityCenter', 'list', location]);

            if (!defenderSettings) return rcb();

            if (defenderSettings.err || !defenderSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Defender Settings: ' + helpers.addError(defenderSettings), location);
                return rcb();
            }

            if (!defenderSettings.data.length) {
                helpers.addResult(results, 0, 'No Defender Settings information found', location);
                return rcb();
            }

            const wdatpIntegration = defenderSettings.data.find((settings) => settings.name && settings.name.toLowerCase() === 'wdatp');
            if (wdatpIntegration && wdatpIntegration.enabled) {
                helpers.addResult(results, 0, 'Endpoint integration is enabled for Microsoft Defender', location, wdatpIntegration.id);
            } else {
                helpers.addResult(results, 2, 'Endpoint integration is not enabled for Microsoft Defender', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
