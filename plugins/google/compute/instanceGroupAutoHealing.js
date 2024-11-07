var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Group Auto Healing Enabled',
    category: 'Compute',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensure that instance groups have auto-healing enabled for high availability.',
    more_info: 'To improve the availability of your application, configure a health check to verify that the application is responding as expected.',
    link: 'https://cloud.google.com/compute/docs/instance-groups/autohealing-instances-in-migs',
    recommended_action: 'Ensure autohealing is enabled for all instance groups.',
    apis: ['instanceGroupManagers:list'],
    realtime_triggers: ['compute.instancegroups.insert', 'compute.instancegroups.delete'],

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

        async.each(regions.instanceGroupManagers, (region, rcb) => {
            var zones = regions.zones;
            var noInstanceGroups = [];
            async.each(zones[region], function(zone, zcb) {
                var instanceGroupManagers = helpers.addSource(cache, source,
                    ['instanceGroupManagers', 'list', zone]);

                if (!instanceGroupManagers) return zcb();

                if (instanceGroupManagers.err || !instanceGroupManagers.data) {
                    helpers.addResult(results, 3, 'Unable to query instance groups', region, null, null, instanceGroupManagers.err);
                    return zcb();
                }

                if (!instanceGroupManagers.data.length) {
                    noInstanceGroups.push(zone);
                    return zcb();
                }

                instanceGroupManagers.data.forEach(instanceGroupManager => {
                    if (!instanceGroupManager.id || !instanceGroupManager.creationTimestamp) return;

                    let resource = helpers.createResourceName('instanceGroupManagers', instanceGroupManager.name, project, 'zone', zone);

                    if (instanceGroupManager.autoHealingPolicies && instanceGroupManager.autoHealingPolicies.length) {
                        helpers.addResult(results, 0,
                            'Instance Group has auto healing enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Instance Group does not have auto healing enabled', region, resource);
                    }
                });
                zcb();
            }, function() {
                if (noInstanceGroups.length) {
                    helpers.addResult(results, 0, `No instance groups found in following zones: ${noInstanceGroups.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};