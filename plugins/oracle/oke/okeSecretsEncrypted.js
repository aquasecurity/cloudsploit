var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'OKE Secrets Encrypted',
    category: 'OKE',
    domain: 'Containers',
    description: 'Ensures the OKE secret objects have encryption enabled using desired protection level.',
    more_info: 'By default, Kubernetes secret objects are encrypted using an Oracle-managed master encryption key. To have better control over the encryption process, you can use Customer-Managed Keys (CMKs).',
    recommended_action: 'Ensure all OKE clusters have desired encryption level for secret objects.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengencryptingdata.htm',
    apis: ['vault:list', 'keys:list', 'cluster:list', 'cluster:get'],
    settings: {
        oke_encryption_level: {
            name: 'OKE Encryption Level',
            description: 'Desired protection level for OKE Secrets. default: oracle-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key',
            regex: '^(default|cloudcmek|cloudhsm)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var keysObj = {};

        let desiredEncryptionLevelStr = settings.oke_encryption_level || this.settings.oke_encryption_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        async.series([
            function(cb) {
                async.each(regions.keys, function(region, rcb) {
                    let keys = helpers.addSource(
                        cache, source, ['keys', 'list', region]);
                    if (keys && keys.data && keys.data.length) helpers.listToObj(keysObj, keys.data, 'id');
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.cluster, function(region, rcb) {

                    if (helpers.checkRegionSubscription(cache, source, results, region)) {

                        var clusters = helpers.addSource(cache, source,
                            ['cluster', 'get', region]);

                        if (!clusters) return rcb();

                        if (clusters.err || !clusters.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for OKE clusters: ' + helpers.addError(clusters), region);
                            return rcb();
                        }

                        if (!clusters.data.length) {
                            helpers.addResult(results, 0, 'No OKE clusters found', region);
                            return rcb();
                        }

                        clusters.data.forEach(cluster => {
                            if (cluster.lifecycleState && cluster.lifecycleState === 'DELETED') return;

                            let currentEncryptionLevel =1; //default 

                            if (cluster.kmsKeyId) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[cluster.kmsKeyId], helpers.PROTECTION_LEVELS);
                            } 

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `OKE cluster (${cluster.name}) has secret encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, region, cluster.id);
                            } else {
                                helpers.addResult(results, 2,
                                    `OKE cluster (${cluster.name}) has secret encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, region, cluster.id);
                            }
                        });
                    }

                    rcb();
                }, function() {
                    cb();
                });
            }
        ], function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};


