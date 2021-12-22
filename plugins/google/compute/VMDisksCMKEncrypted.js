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
    apis: ['disks:list', 'projects:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        disk_encryption_level: {
            name: 'Disk Encryption Protection Level',
            description: 'Desired protection level for Virtual Machine Disk. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        },
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

        let desiredEncryptionLevelStr = settings.disk_encryption_level || this.settings.disk_encryption_level.default;
        var disk_result_limit = parseInt(settings.disk_result_limit || this.settings.disk_result_limit.default);

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
                        var badDisks = [];
                        var goodDisks = [];
                        
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
                        disks.data.forEach(disk => {
                            if (!disk.id || !disk.selfLink || !disk.creationTimestamp) return;
                            let currentEncryptionLevel;

                            if (disk.diskEncryptionKey && disk.diskEncryptionKey.kmsKeyName) {
                                currentEncryptionLevel = helpers.getProtectionLevel((keysArr.find(key => key.name && disk.diskEncryptionKey.kmsKeyName.includes(key.name))), helpers.PROTECTION_LEVELS);
                            } else {
                                currentEncryptionLevel = 1; //default
                            }

                            if (currentEncryptionLevel < desiredEncryptionLevel) {
                                badDisks.push(disk.name);
                            } else {
                                goodDisks.push(disk.name);
                            }
                        });

                        if (badDisks.length) {
                            if (badDisks.length > disk_result_limit) {
                                helpers.addResult(results, 2,
                                    `${badDisks.length} disks have encryption level less than desired encryption level`, region);
                            } else {
                                badDisks.forEach(disk => {
                                    let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                                    helpers.addResult(results, 2,
                                        'Disk encryption level is less than desired encryption level', region, resource);
                                });
                            }
                        }

                        if (goodDisks.length) {
                            if (goodDisks.length > disk_result_limit) {
                                helpers.addResult(results, 0,
                                    `${goodDisks.length} disks have encryption level greater than or equal to desired encryption level`, region);
                            } else {
                                goodDisks.forEach(disk => {
                                    let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                                    helpers.addResult(results, 0,
                                        'Disk encryption level is greater than or equal to desired encryption level', region, resource);
                                });
                            }
                        }

                        if (!goodDisks.length && !badDisks.length) noDisks.push(zone);

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