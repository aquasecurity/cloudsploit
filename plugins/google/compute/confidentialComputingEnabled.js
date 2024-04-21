var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Confidential Computing Enabled',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that Virtual Machine instances have confidential computing enabled.',
    more_info: 'Confidential computing allows your sensitive data to be encrypted in memory while it is being processesd and does not allow Google to have access to the encryption keys. Enabling confidential computing can help alleviate risks about Google insiders access to your confidential data.',
    link: 'https://cloud.google.com/compute/confidential-vm/docs/about-cvm',
    recommended_action: 'Ensure that all VM instances have confidential computing enabled.',
    apis: ['compute:list'],
    realtime_triggers: ['compute.instances.insert', 'compute.instances.delete'],

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
                    if (instance.confidentialInstanceConfig && instance.confidentialInstanceConfig.enableConfidentialCompute) {
                        helpers.addResult(results, 0,
                            'Confidential Computing is enabled for the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Confidential Computing is disabled for the instance', region, resource);
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
    }
};