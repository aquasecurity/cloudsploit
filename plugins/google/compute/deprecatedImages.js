var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Deprecated Images',
    category: 'Compute',
    description: 'Ensure that Compute instances are not created from deprecated images.',
    more_info: 'Deprecated Compute Disk Images should not be used to create VM instances.',
    link: 'https://cloud.google.com/compute/docs/images/image-management-best-practices',
    recommended_action: 'Ensure that no compute instances are created from deprecated images.',
    apis: ['instances:compute:list', 'disks:list', 'images:list', 'projects:get'],

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
        var images = helpers.addSource(cache, source,
            ['images', 'list', 'global']);

        
        if (!images || images.err || !images.data || !images.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for disk images: ' + helpers.addError(images), 'global', null, null, (images) ? images.err : null);
            return callback(null, results, source);
        }

        async.each(regions.instances.compute, (region, rcb) => {
            var noInstances = [];
            var zones = regions.zones;
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone ]);

                var disks = helpers.addSource(cache, source,
                    ['disks', 'list', zone]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                if (!disks) return zcb();

                if (disks.err || !disks.data) {
                    helpers.addResult(results, 3, 'Unable to query compute disks', region, null, null, disks.err);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    let isDeprecatedImage = false;
                    if (instance.disks && instance.disks.length) {
                        let bootDisk = instance.disks.find(disk => disk.boot == true);
                        if (bootDisk) {
                            let diskInformation = disks.data.find(disk => disk.selfLink === bootDisk.source);
                            if (diskInformation) {
                                let diskImage = images.data.find(image => image.id == diskInformation.sourceImageId);
                                if (diskImage) {
                                    if (diskImage.deprecated && diskImage.deprecated.state && diskImage.deprecated.state.toUpperCase() == 'DEPRECATED') {
                                        isDeprecatedImage = true;
                                    }
                                }
                            }
                        }
                        if (isDeprecatedImage) {
                            helpers.addResult(results, 2,
                                'Instance is created from a deprecated image', region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                'Instance is not created from a deprecated image', region, resource);
                        }
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