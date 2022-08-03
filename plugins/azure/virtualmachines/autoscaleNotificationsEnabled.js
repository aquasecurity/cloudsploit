const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Scale Sets Autoscale Notifications Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Virtual Machine scale sets have autoscale notifications enabled.',
    more_info: 'Autoscale automatically creates new instances when certain metrics are surpassed, or can destroy instances that are being underutilized. Autoscale notifications should be enabled to know about the status of autoscale operation.',
    recommended_action: 'Ensure that autoscale notifications are enabled for all Virtual Machine Scale Sets',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/autoscale/autoscale-overview',
    apis: ['virtualMachineScaleSets:listAll', 'autoscaleSettings:listBySubscription'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachineScaleSets, (location, rcb) => {

            const virtualMachineScaleSets = helpers.addSource(cache, source,
                ['virtualMachineScaleSets', 'listAll', location]);

            if (!virtualMachineScaleSets) return rcb();

            if (virtualMachineScaleSets.err || !virtualMachineScaleSets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Virtual Machine Scale Sets: ' + helpers.addError(virtualMachineScaleSets), location);
                return rcb();
            }

            if (!virtualMachineScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machine Scale Sets found', location);
                return rcb();
            }

            const autoscaleSettings = helpers.addSource(cache, source,
                ['autoscaleSettings', 'listBySubscription', location]);

            if (!autoscaleSettings || autoscaleSettings.err || !autoscaleSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for AutoScale settings: ' + helpers.addError(autoscaleSettings), location);
                return rcb();
            }

            if (!autoscaleSettings.data.length) {
                helpers.addResult(results, 2,
                    'No Virtual Machine Scale Sets have autoscale enabled', location);
                return rcb();
            }

            var asMap = {};
            autoscaleSettings.data.forEach(function(autoscaleSetting) {
                if (autoscaleSetting.targetResourceUri) {
                    asMap[autoscaleSetting.targetResourceUri.toLowerCase()] = autoscaleSetting;
                }
            });

            virtualMachineScaleSets.data.forEach(virtualMachineScaleSet => {
                let autoScaleNotifications = [];
                if (virtualMachineScaleSet.id &&
                    asMap[virtualMachineScaleSet.id.toLowerCase()] &&
                    asMap[virtualMachineScaleSet.id.toLowerCase()].notifications &&
                    asMap[virtualMachineScaleSet.id.toLowerCase()].notifications.length) {
                    autoScaleNotifications = asMap[virtualMachineScaleSet.id.toLowerCase()].notifications;
                }

                let found = autoScaleNotifications.find(notification =>
                    (notification.email && (
                        notification.email.sendToSubscriptionAdministrator ||
                        notification.email.sendToSubscriptionCoAdministrators ||
                        (notification.email.customEmails && notification.email.customEmails.length))) || 
                        (notification.webhooks && notification.webhooks.length));
                if (found) {
                    helpers.addResult(results, 0,
                        'Virtual Machine Scale Set has autoscale notifications enabled', location, virtualMachineScaleSet.id);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine Scale Set has autoscale notifications disabled', location, virtualMachineScaleSet.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
