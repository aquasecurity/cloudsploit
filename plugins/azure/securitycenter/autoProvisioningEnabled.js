const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Auto Provisioning Enabled',
    category: 'Security Center',
    description: 'Ensures that automatic provisioning of the monitoring agent is enabled',
    more_info: 'The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, and endpoint protection and provides alerts.',
    recommended_action: 'Ensure that the data collection settings of the subscription have Auto Provisioning set to enabled.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-data-collection',
    apis: ['autoProvisioningSettings:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.autoProvisioningSettings, (location, rcb) => {
            const autoProvisioningSettings = helpers.addSource( cache, source, 
                ['autoProvisioningSettings', 'list', location]);

            if (!autoProvisioningSettings) return rcb();

            if (autoProvisioningSettings.err || !autoProvisioningSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query auto provisioning settings: ' + helpers.addError(autoProvisioningSettings),location);
                return rcb();
            }

            if (!autoProvisioningSettings.data.length) {
                helpers.addResult(results, 2, 'No existing auto provisioning settings found', location);
                return rcb();
            }

            autoProvisioningSettings.data.forEach(function(aps){
                if (aps.autoProvision && aps.autoProvision.toLowerCase() == 'on') {
                    helpers.addResult(results, 0, 'Monitoring Agent Auto Provisioning is enabled', location, aps.id);
                } else {
                    helpers.addResult(results, 2, 'Monitoring Agent Auto Provisioning is disabled', location, aps.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
