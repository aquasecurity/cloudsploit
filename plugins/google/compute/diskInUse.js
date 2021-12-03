var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk In Use',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that there are no unused Compute disks.',
    more_info: 'Unused Compute disks should be deleted to prevent accidental exposure of data and to avoid unnecessary billing.',
    link: 'https://cloud.google.com/compute/docs/disks',
    recommended_action: 'Delete unused Compute disks.',
    apis: ['disks:aggregatedList', 'projects:get'],
    settings: {
        disk_result_limit: {
            name: 'Disk In Use Result Limit',
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

        let disks = helpers.addSource(cache, source,
            ['disks', 'aggregatedList', ['global']]);

        if (!disks) return callback(null, results, source);

        if (disks.err || !disks.data) {
            helpers.addResult(results, 3, 'Unable to query compute disks', 'global', null, null, disks.err);
            return callback(null, results, source);
        }

        regions.all_regions.forEach(region => {
            var noDisks = [];
            var zones = regions.zones;
            var badDisks = [];
            var goodDisks = [];
            let disksInRegion = [];
            let regionData = disks.data[`regions/${region}`];

            if (regionData && regionData['disks'] && regionData['disks'].length) {
                disksInRegion = disks.data[`regions/${region}`].disks.map(disk => { return {...disk, locationType: 'region', location: region};});
            }
        
            zones[region].forEach(zone => {
                let disksInZone = [];
                let zoneData = disks.data[`zones/${zone}`];
               
                if (zoneData && zoneData['disks'] && zoneData['disks'].length) {
                    disksInZone = disks.data[`zones/${zone}`].disks.map(disk => { return {...disk, locationType: 'zone', location: zone};});
                }

                if (!disksInZone.length) {
                    noDisks.push(zone);
                }

                disksInRegion = disksInRegion.concat(disksInZone);
            });

            disksInRegion.forEach(disk => {
                if (!disk.id || !disk.creationTimestamp) return;

                if (disk.users && disk.users.length) {
                    goodDisks.push(disk);
                } else {
                    badDisks.push(disk);
                }
            });

            if (badDisks.length) {
                if (badDisks.length > disk_result_limit) {
                    helpers.addResult(results, 2,
                        `${badDisks.length} disks are not in use`, region);
                } else {
                    badDisks.forEach(disk => {
                        let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);
                        helpers.addResult(results, 2,
                            'Disk is not in use', region, resource);
                    });
                }
            }
        
            if (goodDisks.length) {
                if (goodDisks.length > disk_result_limit) {
                    helpers.addResult(results, 0,
                        `${goodDisks.length} disks are in use`, region);
                } else {
                    goodDisks.forEach(disk => {
                        let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);
                        helpers.addResult(results, 0,
                            'Disk is in use', region, resource);
                    });
                }
            } 

            if (noDisks.length) {
                if (!goodDisks.length && !badDisks.length) {
                    helpers.addResult(results, 0, 'No compute disks found in the region', region);
                } else {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
            }
        });
        callback(null, results, source);
    }
};