var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Redshift Encryption Enabled',
	category: 'Redshift',
	description: 'Ensures at-rest encryption is setup for Redshift clusters',
	more_info: 'AWS provides at-read encryption for Redshift clusters which should be enabled to ensure the integrity of data stored within the cluster.',
	link: 'http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html',
	recommended_action: 'Redshift does not currently allow modifications to encryption after the cluster has been launched, so a new cluster will need to be created with encryption enabled.',
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

				if (cluster.Encrypted) {
					helpers.addResult(results, 1, 'Redshift cluster is encrypted', region, clusterResource);
				} else {
					helpers.addResult(results, 0, 'Redshift cluster is not encrypted', region, clusterResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
