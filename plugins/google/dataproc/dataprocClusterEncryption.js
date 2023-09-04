var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataproc Cluster Encryption',
    category: 'Dataproc',
    domain: 'Compute',
    description: 'Ensure that Dataproc clusters have encryption enabled using desired protection level.',
    more_info: 'By default, all dataproc clusters are encrypted using Google-managed keys. To have better control over how your dataproc clusters are encrypted, you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/customer-managed-encryption',
    recommended_action: 'Ensure that all Dataproc clusters have desired encryption level.',
    apis: ['dataproc:list', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        dataproc_cluster_encryption_level: {
            name: 'Dataproc Cluster Encryption Level',
            description: 'Desired protection level for Dataproc clusters. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.dataproc_cluster_encryption_level || this.settings.dataproc_cluster_encryption_level.default;
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
                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.dataproc, function(region, rcb) {

                    let clusters = helpers.addSource(
                        cache, source, ['dataproc', 'list', region]);

                    if (!clusters) return rcb();

                    if (clusters.err || !clusters.data) {
                        helpers.addResult(results, 3, 'Unable to query Dataproc clusters: ' + helpers.addError(clusters), region, null, null, clusters.err);
                        return rcb();
                    }

                    if (!clusters.data.length) {
                        helpers.addResult(results, 0, 'No Dataproc clusters found', region);
                        return rcb();
                    }
                    
                    if (clusters && clusters.data) {
                        clusters.data.forEach(cluster => {
                            if (!cluster.clusterName) return;

                            let resource = helpers.createResourceName('clusters', cluster.clusterName, project, 'region', region);
                            let currentEncryptionLevel;
                           
                            if (cluster && cluster.config && cluster.config.encryptionConfig && cluster.config.encryptionConfig.gcePdKmsKeyName
                                && keysObj[cluster.config.encryptionConfig.gcePdKmsKeyName]) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[cluster.config.encryptionConfig.gcePdKmsKeyName], helpers.PROTECTION_LEVELS);
                            } else {
                                currentEncryptionLevel = 1; //default
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `Dataproc cluster has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                    region, resource);
                            } else {
                                helpers.addResult(results, 2,
                                    `Dataproc cluster has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                    region, resource);
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