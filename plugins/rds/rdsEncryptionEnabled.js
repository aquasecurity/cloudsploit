var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Encryption Enabled',
	category: 'RDS',
	description: 'Ensures at-rest encryption is setup for RDS instances',
	more_info: 'AWS provides at-read encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
	recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.',
	apis: ['RDS:describeDBInstances', 'RDS:describeOptionGroups'],
	compliance: {
        hipaa: 'All data in HIPAA environments must be encrypted, including ' +
        		'data at rest. RDS encryption ensures that this HIPAA control ' +
        		'is implemented by providing KMS-backed encryption for all RDS ' +
        		'data.'
    },

	run: function(cache, settings, callback) {
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
				var instance = describeDBInstances.data[i];
				var dbResource = instance.DBInstanceArn;
				var group = instance.OptionGroupMemberships[0].OptionGroupName;

				// Evaluate Engine - If Oracle, check the option group for TDE
				if (instance.Engine = 'oracle' || 'sql') {

					var describeOptionGroups = helpers.addSource(cache, source,
						['rds', 'describeOptionGroups', region, group]);

					if (describeOptionGroups.data) {
						helpers.addResult(results, 0, 'Encryption at rest is enabled ' + group, region, dbResource);
					} else {
						helpers.addResult(results, 2, 'Encryption at rest is not enabled ' + group, region, dbResource);
				    }
				}
				else if (instance.StorageEncrypted) {
					helpers.addResult(results, 0, 'Encryption at rest is enabled', region, dbResource);
				}
				else {
					helpers.addResult(results, 1, 'Encryption at rest is not enabled', region, dbResource);
				}
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
