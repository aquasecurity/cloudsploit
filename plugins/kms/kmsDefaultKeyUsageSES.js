var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'KMS Default Key Usage for SES',
	category: 'KMS',
	description: 'Checks SES service to ensure the default KMS key is not being used',
	more_info: 'It is recommended not to use the default key to avoid encrypting disparate sets of data with the same key. Each application should have its own customer-managed KMS key',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html',
	recommended_action: 'Avoid using the default KMS key',
	apis: ['SES:describeActiveReceiptRuleSet', 'KMS:listKeys', 'KMS:describeKey'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var reg = 0;

        async.each(helpers.regions.kms, function(region, rcb) {
			
			
			// for SES
            var describeActiveReceiptRuleSet = helpers.addSource(cache, source, ['ses', 'describeActiveReceiptRuleSet', region]);
            
            if (!describeActiveReceiptRuleSet) return rcb();

			if (describeActiveReceiptRuleSet.err || !describeActiveReceiptRuleSet.data) {
				helpers.addResult(results, 3,
					'Unable to query for SES: ' + helpers.addError(describeActiveReceiptRuleSet), region);
					return rcb();
            }

            if(!(describeActiveReceiptRuleSet.data.length)){
				helpers.addResult(results, 0, 'No SES data Found', region);
				return rcb();
            }

            var services = [];

			for (i in describeActiveReceiptRuleSet.data){
                for (j in describeActiveReceiptRuleSet.data[i].Actions){
                    services.push({
                        serviceName: 'SES',
                        KMSKey: describeActiveReceiptRuleSet.data[i].Actions[j].S3Action.KmsKeyArn
                    });
                }
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