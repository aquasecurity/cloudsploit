var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable WDATP Integration',
    category: 'Defender',
    domain: 'Management and Governance',
    description: 'Ensures that Microsoft Defender for Endpoint integration is enabled for Microsoft Defender for Cloud.',
    more_info: 'WDATP integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration helps to spot abnormalities, detect and respond to advanced attacks on Windows server endpoints monitored by Microsoft Defender for Cloud. Windows Defender ATP in Microsoft Defender for Cloud supports detection on Windows Server 2016, 2012 R2, and 2008 R2 SP1 operating systems in a Standard service subscription.',
    recommended_action: 'Ensure that Microsoft Defender for Endpoint integration is selected with Microsoft Defender for Cloud.',
    link: 'https://docs.microsoft.com/en-in/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows',
    apis: ['securityCenter:list'],

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

            const wdatpIntegration = defenderSettings.data.find((settings) => settings.name.toLowerCase() === 'wdatp');
            if (wdatpIntegration && wdatpIntegration.enabled) {
                helpers.addResult(results, 0, 'WDATP integration is enabled for Microsoft Defender', location, wdatpIntegration.id);
            } else {
                helpers.addResult(results, 2, 'WDATP integration is not enabled for Microsoft Defender', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
