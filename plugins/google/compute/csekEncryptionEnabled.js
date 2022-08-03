var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CSEK Encryption Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures Customer Supplied Encryption Key Encryption is enabled on disks',
    more_info: 'Google encrypts all disks at rest by default. By using CSEK only the users with the key can access the disk. Anyone else, including Google, cannot access the disk data.',
    link: 'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption',
    recommended_action: 'CSEK can only be configured when creating a disk. Delete the disk and redeploy with CSEK.',
    apis: ['disks:aggregatedList'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
            'Enabling encryption of disk data helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
            'Encryption should be enabled for all disks storing this ' +
            'type of data.'
    },

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
                if (!disk.id) return;

                let resource = helpers.createResourceName('disks', disk.name, project, disk.locationType, disk.location);

                if (disk.creationTimestamp &&
                    disk.diskEncryptionKey &&
                    Object.keys(disk.diskEncryptionKey) &&
                    Object.keys(disk.diskEncryptionKey).length) {
                    helpers.addResult(results, 0,
                        'CSEK Encryption is enabled for disk', region, resource);
                } else if (disk.creationTimestamp) {
                    helpers.addResult(results, 2,
                        'CSEK Encryption is disabled for disk', region, resource);
                }
            });

            if (noDisks.length) {
                helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
            }
        });
        callback(null, results, source);
    }
};