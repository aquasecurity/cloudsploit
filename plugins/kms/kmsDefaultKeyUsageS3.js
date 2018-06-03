var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'KMS Default Key Usage for S3',
	category: 'KMS',
	description: 'Checks S3 service to ensure the default KMS key is not being used',
	more_info: 'It is recommended not to use the default key to avoid encrypting disparate sets of data with the same key. Each application should have its own customer-managed KMS key',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html',
	recommended_action: 'Avoid using the default KMS key',
	apis: ['S3:listBuckets', 'S3:getBucketEncryption', 'KMS:listKeys', 'KMS:describeKey'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var reg = 0;

		async.each(helpers.regions.kms, function(region, rcb){

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
					return kcb();
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




				// List S3 Buckets
			var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

			if (!listBuckets) return kcb();

			if (listBuckets.err || !listBuckets.data) {
				helpers.addResult(results, 3,
					'Unable to query for S3: ' + helpers.addError(listBuckets), region);
				return kcb();
			}

			if (!listBuckets.data.length) {
				helpers.addResult(results, 0, 'No S3 keys found', region);
				return kcb();
			}

			async.each(listBuckets.data, function(bucket, scb){
				
				// For S3 encryption
				// ***Requires a bucket name
				var getBucketEncryption = helpers.addSource(cache, source, ['s3', 'getBucketEncryption', region, bucket.Name]);
				
				if (!getBucketEncryption) return scb();
				
				if (getBucketEncryption.err || !getBucketEncryption.data) {
					helpers.addResult(results, 3,
						'Unable to query for S3: ' + helpers.addError(getBucketEncryption), region);
					return scb();
				}

				if (!getBucketEncryption.data.length) {
					helpers.addResult(results, 0, 'No KMS keys found for S3', region);
					return scb();
				}
				var services = [];
				for (i in getBucketEncryption.data){
					for (j in getBucketEncryption.data[i].Rules){
						services.push({
							serviceName: 'S3',
							KMSKey: getBucketEncryption.data[i].Rules[j].ApplyServerSideEncryptionByDefault.KMSMasterKeyID
						});
					}
				}

				for (i in defaultKeys){
                    for (j in services){
                        if (defaultKeys[i] === services.KMSKey){
                            reg++;
                            helpers.addResult(results, 2, 'defult kms key in use', region, defaultKeys[i]);
                        }
                    }
				}
				

				scb();
			}, function(){ 
				kcb();
			});
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