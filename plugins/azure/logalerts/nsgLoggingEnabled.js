var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Network Security Groups Logging Enabled',
    category: 'Log Alerts',
    description: 'Ensures Activity Log alerts for the create or update and delete Network Security Group events are enabled',
    more_info: 'Monitoring for create or update and delete Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Network Security Group create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],
    remediation_min_version: '202011191613',
    remediation_description: 'A Network Security Group log alert will be created to monitor create, update and delete actions',
    apis_remediate: ['activityLogAlerts:listBySubscriptionId'],
    remediation_inputs: {
        nsgResourceGroup: {
            name: '(Mandatory) Resource Group Name',
            description: 'Name of the Resource Group log alerts will be created in',
            regex: '^[-_.a-zA-Z0-9]{1,120}$',
            required: true
        },
        nsgActionGroup: {
            name: '(Mandatory) Action Group Name',
            description: 'Name of the Action Group to send alerts to',
            regex: '^[-_.a-zA-Z0-9]{1,120}$',
            required: true
        }
    },
    actions: {remediate:['activityLogAlerts:write'], rollback:['activityLogAlerts:write']},
    permissions: {remediate: ['activityLogAlerts:write'], rollback: ['activityLogAlerts:write']},
    realtime_triggers: ['microsoftinsights:activitylogalerts:write', 'microsoftinsights:activitylogalerts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {

            var conditionResource = 'microsoft.network/networksecuritygroups';

            var text = 'Network Security Groups';

            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        // inputs specific to the plugin
        var pluginName = 'nsgLoggingEnabled';
        var method = 'PUT';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2017-04-01';

        if (settings.input && settings.input.nsgResourceGroup && settings.input.nsgActionGroup) {
            var thisResource =  resource + `/resourceGroups/${settings.input.nsgResourceGroup}/providers/microsoft.insights/activityLogAlerts/AquaWaveNSGLogAlert`;

            var scopedSubscriptionArr = resource.split('');
            scopedSubscriptionArr.shift();
            var scopedSubscription = scopedSubscriptionArr.join('');
            // create the params necessary for the remediation
            var body = {
                'location': 'global',
                'properties': {
                    'scopes': [scopedSubscription],
                    'enabled': true,
                    'condition': {
                        'allOf': [
                            {
                                'field': 'category',
                                'equals': 'Administrative'
                            },
                            {
                                'field': 'level',
                                'equals': 'Warning'
                            },
                            {
                                'field': 'resourceType',
                                'equals': 'Microsoft.Network/networkSecurityGroups'
                            }
                        ]
                    },
                    'actions': {
                        'actionGroups': [
                            {
                                'actionGroupId': `${resource}/resourceGroups/${settings.input.nsgResourceGroup}/providers/microsoft.insights/actionGroups/${settings.input.nsgActionGroup}`,

                            }
                        ]
                    },
                    'description': 'Log alert created by Aqua Wave for Network Security Group create, update and delete actions',
                }
            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {

            };


            helpers.remediatePlugin(config, method, body, baseUrl, thisResource, remediation_file, putCall, pluginName, function(err, action) {
                if (err) return callback(err);
                if (action) action.action = putCall;


                remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                remediation_file['remediate']['actions'][pluginName][resource] = {
                    'Action': 'Created',
                    'Name': 'AquaWaveNSGLogAlert'
                };

                callback(null, action);
            });
        } else {
            callback('Required inputs missing');
        }
    },
    rollback: function(config, cache, settings, resource, callback) {
        return callback('Rollback is not available');
    }
};
