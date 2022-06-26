var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Encryption Enabled',
    category: 'Redshift',
    domain: 'Databases',
    description: 'Ensures at-rest encryption is setup for Redshift clusters',
    more_info: 'AWS provides at-read encryption for Redshift clusters which should be enabled to ensure the integrity of data stored within the cluster.',
    link: 'http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html',
    recommended_action: 'Redshift does not currently allow modifications to encryption after the cluster has been launched, so a new cluster will need to be created with encryption enabled.',
    apis: ['Redshift:describeClusters', 'STS:getCallerIdentity'],
    compliance: {
        hipaa: 'All data in HIPAA environments must be encrypted, including ' +
                'data at rest. Redshift encryption ensures that this HIPAA control ' +
                'is implemented by providing KMS-backed encryption for all Redshift ' +
                'data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            for (var i in describeClusters.data) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var cluster = describeClusters.data[i];
                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                if (cluster.Encrypted) {
                    helpers.addResult(results, 0, 'Redshift cluster is encrypted', region, resource);
                } else {
                    helpers.addResult(results, 1, 'Redshift cluster is not encrypted', region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
