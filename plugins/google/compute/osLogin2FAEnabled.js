var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'OS Login 2FA Enabled',
    category: 'Compute',
    description: 'Ensure that Virtual Machines instances have OS logic feature enabled and configured with Two-Factor Authentication.',
    more_info: 'Enable OS login Two-Factor Authentication (2FA) to add an additional security layer to your VM instances. The risk of your VM instances getting attcked is reduced significantly if 2FA is enabled.',
    link: 'https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication',
    recommended_action: 'Set enable-oslogin-2fa to true in custom metadata for the instance.',
    apis: ['instances:compute:list', 'projects:get'],
    compliance: {
        pci: 'PCI recommends implementing additional security features for ' +
            'any required service. This includes using secured technologies ' +
            'such as SSH.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute', 'list', zone]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    let isEnabled = false;

                    if (instance.metadata && instance.metadata.items && instance.metadata.items.length) {

                        if (instance.metadata.items.find(item => (item.key && item.key.toLowerCase() === 'enable-oslogin-2fa' &&
                            item.value && item.value.toLowerCase() === 'true'))) {
                            isEnabled = true;
                        }
                    }

                    if (isEnabled) {
                        helpers.addResult(results, 0,
                            'OS Login 2FA is enabled for the the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'OS Login 2FA is not enabled for the the instance', region, resource);
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