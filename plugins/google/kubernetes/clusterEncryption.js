var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cluster Encryption Enabled',
    category: 'Kubernetes',
    description: 'Ensure that GKE clusters have KMS encryption enabled to encrypt application-layer secrets.',
    more_info: 'Application-layer secrets encryption adds additional security layer to sensitive data such as Kubernetes secrets stored in etcd.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets',
    recommended_action: 'Ensure that all GKE clusters have the desired application-layer secrets encryption level.',
    apis: ['clusters:list', 'projects:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        kubernetes_cluster_encryption_level: {
            name: 'Kubernetes Cluster Encryption Protection Level',
            description: 'Desired protection level for GKE clusters. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.kubernetes_cluster_encryption_level || this.settings.kubernetes_cluster_encryption_level.default;
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
                async.each(regions.clusters, function(region, rcb) {
                    let clusters = helpers.addSource(cache, source,
                        ['clusters', 'list', region]);

                    if (!clusters) return rcb();

                    if (clusters.err || !clusters.data) {
                        helpers.addResult(results, 3, 'Unable to query Kubernetes clusters', region, null, null, clusters.err);
                        return rcb();
                    }

                    if (!clusters.data.length) {
                        helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                        return rcb();
                    }

                    clusters.data.forEach(cluster => {
                        let location;

                        if (cluster.locations) {
                            location = cluster.locations.length === 1 ? cluster.locations[0] : cluster.locations[0].substring(0, cluster.locations[0].length - 2);
                        } else location = region;

                        let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);
                        let currentEncryptionLevel;

                        if (cluster.databaseEncryption && cluster.databaseEncryption.state &&
                            cluster.databaseEncryption.state.toUpperCase() == 'ENCRYPTED' &&
                            cluster.databaseEncryption.keyName && cluster.databaseEncryption.keyName.length &&
                            keysObj[cluster.databaseEncryption.keyName]) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[cluster.databaseEncryption.keyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }

                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `GKE Cluster has application-layer secrets encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `GKE Cluster has application-layer secrets encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                region, resource);
                        }

                    });

                    rcb();
                }, function() {
                    cb();
                });
            }
        ], function() {
            callback(null, results, source);
        });
    }
};
