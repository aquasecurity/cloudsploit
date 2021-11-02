var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Persistent Disks Auto Delete',
    category: 'Compute',
    description: 'Ensure that auto-delete is disabled for attached persistent disks.',
    more_info: 'When auto-delete is enabled, the attached persistent disk are deleted with VM instance deletion. In cloud environments, you might want to keep the attached persistent disks even when the associated VM instance is deleted.',
    link: 'https://cloud.google.com/compute/docs/disks',
    recommended_action: 'Ensure that auto-delete is disabled for all disks associated with your VM instances.',
    apis: ['disks:list', 'instances:compute:list', 'projects:get'],
    settings: {
        disk_result_limit: {
            name: 'Persistent Disks Auto Delete Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: '20',
        }
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

        var disk_result_limit = parseInt(settings.disk_result_limit || this.settings.disk_result_limit.default);

        var project = projects.data[0].name;

        async.each(regions.disks, (region, rcb) => {
            var noDisks = [];
            var zones = regions.zones;

            async.each(zones[region], function(zone, zcb) {
                var badDisks = [];
                var goodDisks = [];
                var autoDeleteEnabledDisks = [];

                var disks = helpers.addSource(cache, source,
                    ['disks', 'list', zone]);

                if (!disks) return zcb();

                if (disks.err || !disks.data) {
                    helpers.addResult(results, 3,
                        'Unable to query compute disks', region, null, null, disks.err);
                    return zcb();
                }

                if (!disks.data.length) {
                    noDisks.push(zone);
                    return zcb();
                }

                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute', 'list', zone]);

                if (instances.data) {
                    instances.data.forEach(instance => {
                        if (instance.disks && instance.disks.length) {
                            instance.disks.forEach(disk => {
                                if (disk.autoDelete) {
                                    autoDeleteEnabledDisks.push(disk.deviceName);
                                }
                            });
                        }
                    });
                }

                disks.data.forEach(disk => {
                    if (!disk.id || !disk.selfLink || !disk.creationTimestamp) return;

                    if (autoDeleteEnabledDisks.includes(disk.name)) {
                        badDisks.push(disk.name);
                    } else {
                        goodDisks.push(disk.name);
                    }

                });

                if (!goodDisks.length && !badDisks.length) noDisks.push(zone);

                if (badDisks.length) {
                    if (badDisks.length > disk_result_limit) {
                        helpers.addResult(results, 2,
                            `Auto Delete is enabled for ${badDisks.length} disks`, region);
                    } else {
                        badDisks.forEach(disk => {
                            let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                            helpers.addResult(results, 2,
                                'Auto Delete is enabled for disk', region, resource);
                        });
                    }
                }

                if (goodDisks.length) {
                    if (goodDisks.length > disk_result_limit) {
                        helpers.addResult(results, 0,
                            `Auto Delete is disabled for ${goodDisks.length} disks`, region);
                    } else {
                        goodDisks.forEach(disk => {
                            let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                            helpers.addResult(results, 0,
                                'Auto Delete is disabled for disk', region, resource);
                        });
                    }
                }
                zcb();
            }, function() {
                if (noDisks.length) {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};