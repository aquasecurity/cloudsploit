var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Automatic Restart Enabled',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that Virtual Machine instances have automatic restart feature enabled.',
    more_info: 'Automatic Restart sets the virtual machine restart behavior when an instance is crashed or stopped by the system. If it is enabled, Google Cloud Compute Engine restarts the instance if it crashes or is stopped.',
    link: 'https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options#autorestart',
    recommended_action: 'Ensure automatic restart is enabled for all virtual machine instances.',
    apis: ['compute:list'],
    remediation_min_version: '202202080432',
    remediation_description: 'Automatic Restart will be enabled for all virtual machine instances.',
    apis_remediate: ['compute:list', 'projects:get'],
    actions: {remediate:['compute.instances.setScheduling'], rollback:['compute.instances.setScheduling']},
    permissions: {remediate: ['compute.instances.setScheduling'], rollback: ['compute.instances.setScheduling']},
    realtime_triggers: ['compute.instances.setScheduling', 'compute.instances.insert', 'compute.instances.delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;
        async.each(regions.compute, (region, rcb) => {
            var noInstances = [];
            var zones = regions.zones;
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['compute','list', zone ]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (instance.scheduling && instance.scheduling.automaticRestart) {
                        helpers.addResult(results, 0,
                            'Automatic Restart is enabled for the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Automatic Restart is disabled for the instance', region, resource);
                    }
                });
                zcb();
            }, function() {
                if (noInstances.length) {
                    helpers.addResult(results, 0, `No instances found in following zones: ${noInstances.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;

        // inputs specific to the plugin
        var pluginName = 'automaticRestartEnabled';
        var baseUrl = 'https://compute.googleapis.com/compute/v1/{resource}/setScheduling';
        var method = 'POST';
        var putCall = this.actions.remediate;

        // create the params necessary for the remediation
        var body = {
            automaticRestart: true
        };
        // logging
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'automaticRestart': 'Disabled'
        };

        helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
            if (err) return callback(err);
            if (action) action.action = putCall;


            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enabled'
            };

            callback(null, action);
        });
    }
};