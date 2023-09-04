var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VM Disks CMK Encryption',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that Virtual Machine instances are encrypted using customer-managed keys.',
    more_info: 'Google encrypts all disks at rest by default. By using CMKs you can have better control over your disk encryption.',
    link: 'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption',
    recommended_action: 'Ensure that your VM instances have CMK encryption enabled.',
    apis: ['disks:list', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        disk_encryption_level: {
            name: 'Disk Encryption Protection Level',
            description: 'Desired protection level for Virtual Machine Disk. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.disk_encryption_level || this.settings.disk_encryption_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);
        var keysArr = [];

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.series([
            function(cb) {
                async.each(regions.cryptoKeys, function(region, rcb) {
                    let cryptoKeys = helpers.addSource(
                        cache, source, ['cryptoKeys', 'list', region]);
                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) keysArr = cryptoKeys.data;
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.disks, (region, rcb) => {
                    var noDisks = [];
                    var zones = regions.zones;

                    async.each(zones[region], function(zone, zcb) {
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

                        var disksFound = false;

                        disks.data.forEach(disk => {
                            if (!disk.id || !disk.selfLink || !disk.creationTimestamp) return;

                            disksFound = true;

                            let currentEncryptionLevel;

                            if (disk.diskEncryptionKey && disk.diskEncryptionKey.kmsKeyName) {
                                currentEncryptionLevel = helpers.getProtectionLevel((keysArr.find(key => key.name && disk.diskEncryptionKey.kmsKeyName.includes(key.name))), helpers.PROTECTION_LEVELS);
                            } else {
                                currentEncryptionLevel = 1; //default
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];
                            let resource = helpers.createResourceName('disks', disk.name, project, 'zone', zone);

                            if (currentEncryptionLevel < desiredEncryptionLevel) {
                                helpers.addResult(results, 2,
                                    `Disk encryption level ${currentEncryptionLevelStr} is less than desired encryption level ${desiredEncryptionLevelStr}`, region, resource);
                            } else {
                                helpers.addResult(results, 0,
                                    `Disk encryption level ${currentEncryptionLevelStr} is greater than or equal to desired encryption level ${desiredEncryptionLevelStr}`, region, resource);
                            }
                        });

                        if (!disksFound) noDisks.push(zone);

                        zcb();
                    }, function() {
                        if (noDisks.length) {
                            helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                        }
                        rcb();
                    });
                }, function() {
                    cb();
                });
            }
        ], function() {
            callback(null, results, source);
        });
    }
};