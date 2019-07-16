const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Autoscale Enabled',
    category: 'Monitor',
    description: 'Ensure Autoscaling is enabled on Resource Groups.',
    more_info: 'Enabling Autoscale increases efficency and improves cost management for resources.',
    recommended_action: '1. Navigate to the Monitor category. 2. Select the autoscale blade under settings. 3. Choose the resource group. 4. Configure autoscaling.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-use-availability-zones',
    apis: ['resourceGroups:list', 'autoscaleSettings:listByResourceGroup'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.autoscaleSettings, (location, rcb) => {

            const autoscaleSettings = helpers.addSource(cache, source,
                ['autoscaleSettings', 'listByResourceGroup', location]);

            if (!autoscaleSettings) return rcb();

            if (autoscaleSettings.err || !autoscaleSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query Autoscale settings: ' + helpers.addError(autoscaleSettings), location);
                return rcb();
            }

            if (!autoscaleSettings.data.length) {
                helpers.addResult(results, 0,
                    'No existing Autoscale settings enabled', location);
                return rcb();
            }

            for (var a in autoscaleSettings.data) {
                var autoscaleSetting = autoscaleSettings.data[a];
                const autoscaleResource = ((autoscaleSetting.autoscaleSettingResourceName &&
                    autoscaleSetting.autoscaleSettingResourceName.indexOf('-') > -1) ? autoscaleSetting.autoscaleSettingResourceName.split("-") : undefined);
                if (autoscaleResource) {
                    const autoscaleResourceName = autoscaleResource[1];
                    if (autoscaleSetting.enabled) {
                        helpers.addResult(results, 0,
                            'Autoscale is enabled for the resource group', location, autoscaleResourceName);
                    } else {
                        helpers.addResult(results, 1,
                            'Autoscale is disabled for the resource group', location, autoscaleResourceName);
                    }
                } else {
                    helpers.addResult(results, 3,
                        'Unable to read Autoscale settings', location);
                }
            }
            
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};
