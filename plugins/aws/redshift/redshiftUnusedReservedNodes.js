var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Unused Reserved Nodes',
    category: 'Redshift',
    description: 'Ensures that Amazon Redshift Reserved Nodes are being utilized.',
    more_info: 'Amazon Redshift reserved nodes must be utilized to avoid unnecessary billing.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/purchase-reserved-node-instance.html',
    recommended_action: 'Provision new Redshift clusters matching the criteria of reserved nodes',
    apis: ['Redshift:describeClusters', 'Redshift:describeReservedNodes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            var describeReservedNodes = helpers.addSource(cache, source,
                ['redshift', 'describeReservedNodes', region]);
    
            if (!describeReservedNodes) return rcb();

            if (describeReservedNodes.err || !describeReservedNodes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Redshift reserved nodes: ' + helpers.addError(describeReservedNodes), region);
                return rcb();
            }

            if (!describeReservedNodes.data.length) {
                helpers.addResult(results, 0, 'No Redshift reserved nodes found', region);
                return rcb();
            }

            if (!describeClusters || describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
                return rcb();
            }

            var usedReservedNodes = [];
            describeClusters.data.forEach(cluster => {
                if (!cluster.ClusterIdentifier) return;

                if (!usedReservedNodes.includes(cluster.NodeType)) {
                    usedReservedNodes.push(cluster.NodeType);
                }
            });

            describeReservedNodes.data.forEach(node => {
                if (usedReservedNodes.includes(node.NodeType)) {
                    helpers.addResult(results, 0,
                        `Redshift reserved node "${node.ReservedNodeId}" is being used`,
                        region, node.ReservedNodeId);
                } else {
                    helpers.addResult(results, 2,
                        `Redshift reserved node "${node.ReservedNodeId}" is not being used`,
                        region, node.ReservedNodeId);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
