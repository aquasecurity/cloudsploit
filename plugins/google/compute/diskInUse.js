var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disk In Use',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that there are no unused Compute disks.',
    more_info: 'Unused Compute disks should be deleted to prevent accidental exposure of data and to avoid unnecessary billing.',
    link: 'https://cloud.google.com/compute/docs/disks',
    recommended_action: 'Delete unused Compute disks.',
    apis: ['disks:aggregatedList'],
    
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

        let disks = helpers.addSource(cache, source,
            ['disks', 'aggregatedList', ['global']]);

        if (!disks) return callback(null, results, source);

        if (disks.err || !disks.data) {
            helpers.addResult(results, 3, 'Unable to query compute disks', 'global', null, null, disks.err);
            return callback(null, results, source);
        }
        
        disks.data.forEach(diskData => {
            regions.all_regions.forEach(region => {
                var noDisks = [];
                var zones = regions.zones;
                let disksInRegion = [];
                let regionData = diskData[`regions/${region}`];
    
                if (regionData && regionData['disks'] && regionData['disks'].length) {
                    disksInRegion = diskData[`regions/${region}`].disks.map(disk => { return {...disk, locationType: 'region', location: region};});
                }
            
                zones[region].forEach(zone => {
                    let disksInZone = [];
                    let zoneData = diskData[`zones/${zone}`];
                   
                    if (zoneData && zoneData['disks'] && zoneData['disks'].length) {
                        disksInZone = diskData[`zones/${zone}`].disks.map(disk => { return {...disk, locationType: 'zone', location: zone};});
                    }
    
                    if (!disksInZone.length) {
                        noDisks.push(zone);
                    }
    
                    disksInRegion = disksInRegion.concat(disksInZone);
                });
    
                disksInRegion.forEach(disk => {
                    if (!disk.id || !disk.creationTimestamp) return;
    
                    let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);
    
                    if (disk.users && disk.users.length) {
                        helpers.addResult(results, 0,
                            'Disk is in use', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Disk is not in use', region, resource);
                    }
                });
    
                if (noDisks.length) {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
            });
        });
       
        callback(null, results, source);
    }
};