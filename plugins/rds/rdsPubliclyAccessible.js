var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Publicly Accessible',
	category: 'RDS',
	description: 'Ensures RDS instances are not launched into the public cloud',
	more_info: 'Unless there is a specific business requirement, RDS instances should not have a public endpoint and should be accessed from within a VPC only.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html',
	recommended_action: 'Remove the public endpoint from the RDS instance',
	apis: ['RDS:describeDBInstances'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.rds, function(region, rcb){
			var describeDBInstances = helpers.addSource(cache, source,
				['rds', 'describeDBInstances', region]);

			if (!describeDBInstances) return rcb();

			if (describeDBInstances.err || !describeDBInstances.data) {
				helpers.addResult(results, 3,
					'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
				return rcb();
			}

			if (!describeDBInstances.data.length) {
				helpers.addResult(results, 0, 'No RDS instances found', region);
				return rcb();
			}

			for (i in describeDBInstances.data) {
				// For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
				var db = describeDBInstances.data[i];
				var dbResource = db.DBInstanceArn;

				if (db.PubliclyAccessible) {
					helpers.addResult(results, 1, 'RDS instance is publicly accessible', region, dbResource);
				} else {
					helpers.addResult(results, 0, 'RDS instance is not publicly accessible', region, dbResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
