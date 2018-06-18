var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'KMS Default Key Usage for ElasticTranscoder',
	category: 'KMS',
	description: 'Checks ElasticTranscoder service to ensure the default KMS key is not being used',
	more_info: 'It is recommended not to use the default key to avoid encrypting disparate sets of data with the same key. Each application should have its own customer-managed KMS key',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html',
	recommended_action: 'Avoid using the default KMS key',
	apis: ['ElasticTranscoder:listPipelines', 'KMS:listKeys', 'KMS:describeKey'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var reg = 0;

        async.each(helpers.regions.kms, function(region, rcb) {
			
			
			// for Elastictranscoder
            var listPipelines = helpers.addSource(cache, source, ['elastictranscoder', 'listPipelines', region]);
            
            if (!listPipelines) return rcb();

			if (listPipelines.err || !listPipelines.data) {
				helpers.addResult(results, 3,
					'Unable to query for ElasticTranscoder: ' + helpers.addError(listPipelines), region);
					return rcb();
            }

            if(!(listPipelines.data.length)){
				helpers.addResult(results, 0, 'No ElasticTranscoder data Found', region);
				return rcb();
            }

            var services = [];

			for (i in listPipelines.data){
				services.push({
					serviceName: 'ElasticTranscoder',
					KMSKey: listPipelines.data[i].AwsKmsKeyArn
				});
            }

            // List the KMS Keys
			var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

			if (!listKeys) return rcb();

			if (listKeys.err || !listKeys.data) {
				helpers.addResult(results, 3,
					'Unable to query for KMS: ' + helpers.addError(listKeys), region);
				return rcb();
			}

			if (!listKeys.data.length) {
				helpers.addResult(results, 0, 'No KMS keys found', region);
				return rcb();
            }
            
            async.each(listKeys.data, function(key, kcb){
				// Describe the KMS keys
				var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

				if (!describeKey || describeKey.err || !describeKey.data) {

					helpers.addResult(results, 3,
						'Unable to query for KMS: ' + helpers.addError(describeKey), region);
					return rcb();
				}

				var keysInfo = [];
				for (i in describeKey.data){
					keysInfo.push({
							keyId: describeKey.data[i].KeyId,
							Desc: describeKey.data[i].Description
						});
					}

				var defSTR = 'Default master key (.*)';
				var defaultKeys = [];
				for (i in keysInfo){
					if (keysInfo[i].Desc.match(defSTR)){
						defaultKeys.push(keysInfo[i].keyId);
					}
                }
                var reg = 0;
                for (i in defaultKeys){
                    for (j in services){
                        if (defaultKeys[i] === services.KMSKey){
                            reg++;
                            helpers.addResult(results, 2, 'defult kms key in use', region, defaultKeys[i]);
                        }
                    }
                }
                
				kcb();
			}, function(){
                if (!reg){
                    helpers.addResult(results, 0, 'no defult kms key found in use', region);
                }
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};