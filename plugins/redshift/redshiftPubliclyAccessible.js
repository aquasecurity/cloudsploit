var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Redshift Publicly Accessible',
	category: 'Redshift',
	description: 'Ensures Redshift clusters are not launched into the public cloud',
	more_info: 'Unless there is a specific business requirement, Redshift clusters should not have a public endpoint and should be accessed from within a VPC only.',
	link: 'http://docs.aws.amazon.com/redshift/latest/mgmt/getting-started-cluster-in-vpc.html',
	recommended_action: 'Remove the public endpoint from the Redshift cluster',
	apis: ['Redshift:describeClusters'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.redshift, function(region, rcb){
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

			for (i in describeClusters.data) {
				// For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
				var cluster = describeClusters.data[i];
				var clusterResource = (cluster.Endpoint && cluster.Endpoint.Address) ? cluster.Endpoint.Address : cluster.ClusterIdentifier;

				if (cluster.PubliclyAccessible) {
					helpers.addResult(results, 1, 'Redshift cluster is publicly accessible', region, clusterResource);
				} else {
					helpers.addResult(results, 0, 'Redshift cluster is not publicly accessible', region, clusterResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
