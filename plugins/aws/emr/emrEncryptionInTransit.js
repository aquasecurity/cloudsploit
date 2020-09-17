var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EMR Encryption In Transit',
    category: 'EMR',
    description: 'Ensures encryption in transit is enabled for EMR clusters',
    more_info: 'EMR clusters should be configured to enable encryption in transit.',
    link: 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html',
    recommended_action: 'Update security configuration associated with EMR cluster to enable encryption in transit.',
    apis: ['EMR:listClusters', 'EMR:describeCluster', 'EMR:describeSecurityConfiguration'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.emr, function(region, rcb){
            var listClusters = helpers.addSource(cache, source,
                ['emr', 'listClusters', region]);
            
            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EMR clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No EMR cluster found', region);
                return rcb();
            }

            async.each(listClusters.data, function(cluster, lcb){
                if (!cluster.Id) lcb();

                var describeCluster = helpers.addSource(cache, source,
                    ['emr', 'describeCluster', region, cluster.Id]);
                
                var resource = cluster.ClusterArn;

                if (!describeCluster || describeCluster.err || !describeCluster.data || !describeCluster.data.Cluster) {
                    helpers.addResult(results, 3,
                        'Unable to query for EMR cluster', region, resource);
                    return lcb();
                }

                if (!describeCluster.data.Cluster.SecurityConfiguration) {
                    helpers.addResult(results, 2,
                        'No security configuration found for :' + cluster.Name + ': EMR cluster',
                        region, resource);
                    return lcb();
                }

                var securityConfigurationName = describeCluster.data.Cluster.SecurityConfiguration;

                var describeSecurityConfiguration = helpers.addSource(cache, source,
                    ['emr', 'describeSecurityConfiguration', region, securityConfigurationName]);

                if (!describeSecurityConfiguration ||
                    describeSecurityConfiguration.err ||
                    !describeSecurityConfiguration.data ||
                    !describeSecurityConfiguration.data.SecurityConfiguration) {
                    helpers.addResult(results, 3,
                        'Unable to query for EMR cluster security configuration', region, resource);
                    return lcb();
                }

                try {
                    var clusterSecurityConfiguration = JSON.parse(describeSecurityConfiguration.data.SecurityConfiguration);
                } catch (e) {
                    helpers.addResult(results, 3,
                        'Cluster security configuration is not valid JSON.',
                        region, resource);

                    return lcb();
                }

                if (clusterSecurityConfiguration.EncryptionConfiguration &&
                    clusterSecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption &&
                    clusterSecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption === true &&
                    clusterSecurityConfiguration.EncryptionConfiguration.InTransitEncryptionConfiguration) {
                    helpers.addResult(results, 0,
                        'Encryption in transit is enabled for :' + cluster.Name + ': EMR cluster',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Encryption in transit is not enabled for :' + cluster.Name + ': EMR cluster',
                        region, resource);
                }
                lcb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
