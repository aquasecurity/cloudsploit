var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Nodes Count',
    category: 'Redshift',
    description: 'Ensures that your AWS account has not reached the limit set for the number of Redshift cluster nodes.',
    more_info: 'The number of provisioned Amazon Redshift cluster nodes must be less than the provided nodes limit to avoid reaching the limit and exceeding the set budget.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#working-with-clusters-overview',
    recommended_action: 'Remove Redshift clusters over defined limit',
    apis: ['Redshift:describeClusters'],
    settings: {
        redshift_nodes_count: {
            name: 'Amazon Redshift Nodes Count',
            description: 'Maximum Amazon Redshift nodes count per region',
            regex: '^.*$',
            default: 'false'
        },
    },

    run: function(cache, settings, callback) {
        var redshift_nodes_count = settings.redshift_nodes_count || this.settings.redshift_nodes_count.default;

        if (redshift_nodes_count === 'false') return callback();
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var nodesCount = 0;

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

            describeClusters.data.forEach(cluster => {
                if (!cluster.ClusterIdentifier) return;

                if(cluster.NumberOfNodes) {
                    nodesCount = nodesCount + cluster.NumberOfNodes;
                }
            });

            rcb();
        }, function(){
            if (nodesCount <= redshift_nodes_count) {
                helpers.addResult(results, 0,
                    `Account contains "${nodesCount}" provisioned Redshift nodes of "${redshift_nodes_count}" limit`);
            } else {
                helpers.addResult(results, 2,
                    `Account contains "${nodesCount}" provisioned Redshift nodes of "${redshift_nodes_count}" limit`);
            }

            callback(null, results, source);
        });
    }
};
