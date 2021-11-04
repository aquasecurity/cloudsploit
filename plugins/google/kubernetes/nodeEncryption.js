var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Node Encryption Enabled',
    category: 'Kubernetes',
    domain: 'Containers',
    description: 'Ensure that GKE cluster nodes are encrypted using desired encryption protection level. ',
    more_info: 'Using Customer Managed Keys (CMKs) gives you better control over the encryption/decryption process of your cluster nodes.',
    link: 'https://cloud.google.com/security/encryption/default-encryption',
    recommended_action: 'Ensure that all node pools in GKE clusters have the desired encryption level.',
    apis: ['clusters:list', 'projects:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        kubernetes_node_encryption_level: {
            name: 'Kubernetes Node Encryption Protection Level',
            description: 'Desired protection level for GKE cluster nodes. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.kubernetes_node_encryption_level || this.settings.kubernetes_node_encryption_level.default;

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

                        let nonEncryptedNodes = [];

                        let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);

                        if (cluster.nodePools &&
                            cluster.nodePools.length) {
                            cluster.nodePools.forEach(nodePool => {
                                let currentEncryptionLevel;

                                if (nodePool.config && nodePool.config.bootDiskKmsKey && nodePool.config.bootDiskKmsKey.length && keysObj[nodePool.config.bootDiskKmsKey]) {
                                    currentEncryptionLevel = helpers.getProtectionLevel(keysObj[nodePool.config.bootDiskKmsKey], helpers.PROTECTION_LEVELS);
                                } else {
                                    currentEncryptionLevel = 1; //default
                                }

                                if (currentEncryptionLevel < desiredEncryptionLevel) {
                                    nonEncryptedNodes.push(nodePool.name);
                                }
                            });

                            if (nonEncryptedNodes.length) {
                                helpers.addResult(results, 2,
                                    `These node pools do not have the desired encryption level: ${nonEncryptedNodes.join(', ')}`, region, resource);
                            } else {
                                helpers.addResult(results, 0,
                                    'All node pools have the desired encryption level', region, resource);
                            }

                        } else {
                            helpers.addResult(results, 0, 'No node pools found', region, resource);
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
