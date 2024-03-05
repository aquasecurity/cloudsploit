var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Snapshot Encryption',
    category: 'Compute',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensure Snapshots are encrypted using Customer Managed or Supplied Keys.',
    more_info: 'GCP compute disk snapshots are encrypted with the encryption type of source disk. By default, the compute disks are encrypted using the Google-managed encryption keys. However, to have better control on the encryption process and adhere to compliance requirements, use either customer-managed keys or customer-supplied keys for encryption.',
    link: 'https://cloud.google.com/compute/docs/disks/customer-managed-encryption',
    recommended_action: 'Ensure that all disk snapshots are encrypted using desired protection level.',
    apis: ['snapshots:list', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        snapshot_encryption_level: {
            name: 'Snapshot Encryption Protection Level',
            description: 'Desired protection level for disk snapshot. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        },
    },
    realtime_triggers: ['compute.snapshots.insert', 'compute.snapshots.delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.snapshot_encryption_level || this.settings.snapshot_encryption_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);
        
        var keysObj = {};

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

                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) {
                        helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    }
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {

                let snapshots = helpers.addSource(cache, source,
                    ['snapshots', 'list', 'global']);
        
                if (!snapshots) return callback(null, results, source);
        
                if (snapshots.err || !snapshots.data) {
                    helpers.addResult(results, 3, 'Unable to query for disk snapshots: ' + helpers.addError(snapshots), 'global');
                    return callback(null, results, source);
                }
                if (!snapshots.data.length) {
                    helpers.addResult(results, 0, 'No disk snapshots found', 'global');
                    return callback(null, results, source);
                }
        
                var snapshotsFound = false;
        
                snapshots.data.forEach(snapshot => {

                    if (snapshot.creationTimestamp) {
                        snapshotsFound = true;
                        let resource = helpers.createResourceName('snapshot', snapshot.name, project, 'global');
                        let currentEncryptionLevel = 1; // default

                        if (snapshot.snapshotEncryptionKey && snapshot.snapshotEncryptionKey.kmsKeyName) {
                            let keyName = Object.keys(keysObj).find(key => snapshot.snapshotEncryptionKey.kmsKeyName.includes(key));
                            if (keyName) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[keyName], helpers.PROTECTION_LEVELS);
                            }
                        }

                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `Disk snapshot has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, 'global', resource);
                        } else {
                            helpers.addResult(results, 2,
                                `Disk snapshot has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, 'global', resource);
                        }
                    }
                });
        
                if (!snapshotsFound) {
                    helpers.addResult(results, 0, 'No snapshots found in the project', 'global', project);
                }
                cb();
            }
        ], function() {
            callback(null, results, source);
        });
    }
};