var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Automated Backups',
	category: 'RDS',
	description: 'Ensures automated backups are enabled for RDS instances',
	more_info: 'AWS provides a simple method of backing up RDS instances at a regular interval. This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
	recommended_action: 'Enable automated backups for the RDS instance',
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

				if (db.BackupRetentionPeriod && db.BackupRetentionPeriod > 6) {
					helpers.addResult(results, 0,
						'Automated backups are enabled with sufficient retention (' + db.BackupRetentionPeriod + ' days)',
						region, dbResource);
				} else if (db.BackupRetentionPeriod) {
					helpers.addResult(results, 1,
						'Automated backups are enabled but do not have sufficient retention (' + db.BackupRetentionPeriod + ' days)',
						region, dbResource);
				} else {
					helpers.addResult(results, 2,
						'Automated backups are not enabled',
						region, dbResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
