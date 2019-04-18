var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
	title: 'RDS Logging Enabled',
	category: 'RDS',
	description: 'Ensures logging is configured for RDS instances',
	more_info: 'Logging database level events enables teams to analyze events for the purpose diagnostics as well as audit tracking for compliance purposes.',
	link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html',
	recommended_action: 'Modify the RDS instance to enable logging as required.',
	apis: ['RDS:describeDBInstances'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		async.each(regions.rds, function(region, rcb){
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
				console.log(db.EnabledCloudwatchLogsExports);

				if (db.EnabledCloudwatchLogsExports) {
					helpers.addResult(results, 0, 'Logging is enabled', region, dbResource);
				} else {
					helpers.addResult(results, 2, 'Logging is not enabled', region, dbResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
