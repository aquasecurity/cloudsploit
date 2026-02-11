var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Encryption In Transit',
    category: 'DocumentDB',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that DocumentDB clusters have TLS/SSL encryption in transit enabled.',
    more_info: 'DocumentDB uses TLS/SSL to encrypt data during transit. The TLS parameter in the cluster parameter group should be set to enabled to require encrypted connections. This ensures that all data transmitted between clients and the DocumentDB cluster is encrypted.',
    recommended_action: 'Modify the cluster parameter group to set the tls parameter to enabled, or create a custom parameter group with TLS enabled and associate it with the cluster.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html',
    apis: ['DocDB:describeDBClusters', 'DocDB:describeDBClusterParameters'],
    realtime_triggers: [ 'docdb:CreateDBCluster', 'docdb:ModifyDBCluster', 'docdb:ModifyDBClusterParameterGroup', 'docdb:CreateDBClusterParameterGroup','docdb:DeleteDBCluster' ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.docdb, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['docdb', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list DocumentDB clusters: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No DocumentDB clusters found', region);
                return rcb();
            }

            async.each(describeDBClusters.data, function(cluster, ccb){
                if (!cluster.DBClusterArn || !cluster.DBClusterIdentifier) return ccb();

                var resource = cluster.DBClusterArn;
                var tlsEnabled = false;

                if (!cluster.DBClusterParameterGroup) {
                    helpers.addResult(results, 2,
                        'DocumentDB cluster does not have a parameter group associated',
                        region, resource);
                    return ccb();
                }

                var parameterGroupName = cluster.DBClusterParameterGroup;

                var parameters = helpers.addSource(cache, source,
                    ['docdb', 'describeDBClusterParameters', region, parameterGroupName]);

                if (!parameters || parameters.err || !parameters.data) {
                    helpers.addResult(results, 3,
                        `Unable to query cluster parameters: ${helpers.addError(parameters)}`,
                        region, resource);
                    return ccb();
                }

                if (!parameters.data.Parameters) {
                    helpers.addResult(results, 2,
                        'DocumentDB cluster does not have TLS encryption in transit enabled',
                        region, resource);
                    return ccb();
                }

                for (var param of parameters.data.Parameters) {
                    if (param.ParameterName && param.ParameterName === 'tls' &&
                        param.ParameterValue && 
                        (param.ParameterValue.toLowerCase() === 'enabled' || param.ParameterValue === '1')) {
                        tlsEnabled = true;
                        break;
                    }
                }

                if (tlsEnabled) {
                    helpers.addResult(results, 0,
                        'DocumentDB cluster has TLS encryption in transit enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'DocumentDB cluster does not have TLS encryption in transit enabled',
                        region, resource);
                }

                ccb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
