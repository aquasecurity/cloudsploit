var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Encryption Enabled',
	category: 'RDS',
	description: 'Ensures at-rest encryption is setup for RDS instances',
	more_info: 'AWS provides at-read encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
	recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.',
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

				if (db.StorageEncrypted) {
					helpers.addResult(results, 0, 'Encryption at rest is enabled', region, dbResource);
				} else {
					helpers.addResult(results, 1, 'Encryption at rest is not enabled', region, dbResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
