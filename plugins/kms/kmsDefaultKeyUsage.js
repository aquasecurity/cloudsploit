var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'KMS Default Key Usage',
	category: 'KMS',
	description: 'Checks AWS services to ensure the default KMS key is not being used',
	more_info: 'It is recommended not to use the default key to avoid encrypting disparate sets of data with the same key. Each application should have its own customer-managed KMS key',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html',
	recommended_action: 'Avoid using the default KMS key',
	apis: ['KMS:listKeys', 'KMS:describeKey', 'CloudTrail:describeTrails', 'EC2:describeVolumes',
		   'ElasticTranscoder:listPipelines', 'RDS:describeDBInstances', 'Redshift:describeClusters',
		   'S3:listBuckets', 'S3:getBucketEncryption', 'SES:describeActiveReceiptRuleSet',
		   'Workspaces:describeWorkspaces'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var reg = 0;

        async.each(helpers.regions.kms, function(region, rcb) {
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

            // Master list of services
            var services = [];
			
			// For CloudTrail
			var describeTrails = helpers.addSource(cache, source, ['cloudtrail', 'describeTrails', region]);

			if (describeTrails) {
				if (describeTrails.err || !describeTrails.data) {
					helpers.addResult(results, 3,
						'Unable to query for CloudTrail: ' + helpers.addError(describeTrails), region);
	            } else {
	            	for (i in describeTrails.data){
						if (describeTrails.data[i].KmsKeyId){
							services.push({
								serviceName: 'CloudTrail',
								KMSKey: describeTrails.data[i].KmsKeyId
							});
						}
		            }
	            }
			}	

            // For EBS
            var describeVolumes = helpers.addSource(cache, source, ['ec2', 'describeVolumes', region]);

			if (describeVolumes) {
				if (describeVolumes.err || !describeVolumes.data) {
					helpers.addResult(results, 3,
						'Unable to query for EBS volumes: ' + helpers.addError(describeVolumes), region);
				} else {
					for (i in describeVolumes.data){			
						if (describeVolumes.data[i].KmsKeyId) {
							services.push({
								serviceName: 'EBS',
								KMSKey: describeVolumes.data[i].KmsKeyId
							});
						}
					}
				}
			}	

			// For ElasticTranscoder
			var listPipelines = helpers.addSource(cache, source, ['elastictranscoder', 'listPipelines', region]);

			if (listPipelines) {
				if (listPipelines.err || !listPipelines.data) {
					helpers.addResult(results, 3,
						'Unable to query for ElasticTranscoder pipelines: ' + helpers.addError(listPipelines), region);
				} else {
					for (i in listPipelines.data){
						if (listPipelines.data[i].AwsKmsKeyArn) {
							services.push({
								serviceName: 'ElasticTranscoder',
								KMSKey: listPipelines.data[i].AwsKmsKeyArn
							});
						}
					}
				}
			}

			// For RDS
			var describeDBInstances = helpers.addSource(cache, source, ['rds', 'describeDBInstances', region]);

			if (describeDBInstances) {
				if (describeDBInstances.err || !describeDBInstances.data) {
					helpers.addResult(results, 3,
						'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
				} else {
					for (i in describeDBInstances.data){
						if(describeDBInstances.data[i].StorageEncrypted &&
							describeDBInstances.data[i].KmsKeyId){
							services.push({
								serviceName: 'RDS',
								KMSKey: describeDBInstances.data[i].KmsKeyId
							});
						}
					}
				}
			}

			// For Redshift
			var describeClusters = helpers.addSource(cache, source, ['redshift', 'describeClusters', region]);

			if (describeClusters) {
				if (describeClusters.err || !describeClusters.data) {
					helpers.addResult(results, 3,
						'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
				} else {
					for (i in describeClusters.data){
						if(describeClusters.data[i].KmsKeyId){
							services.push({
								serviceName: 'Redshift',
								KMSKey: describeClusters.data[i].KmsKeyId
							});
						}
					}
				}
			}

			// For SES
			var describeActiveReceiptRuleSet = helpers.addSource(cache, source, ['ses', 'describeActiveReceiptRuleSet', region]);

			if (describeActiveReceiptRuleSet) {
				if (describeActiveReceiptRuleSet.err || !describeActiveReceiptRuleSet.data) {
					helpers.addResult(results, 3,
						'Unable to query for SES: ' + helpers.addError(describeActiveReceiptRuleSet), region);
				} else {
					for (i in describeActiveReceiptRuleSet.data){
						if (describeActiveReceiptRuleSet.data[i].Actions) {
							for (j in describeActiveReceiptRuleSet.data[i].Actions){
								if (describeActiveReceiptRuleSet.data[i].Actions[j].S3Action &&
									describeActiveReceiptRuleSet.data[i].Actions[j].S3Action.KmsKeyArn) {
									services.push({
										serviceName: 'SES',
										KMSKey: describeActiveReceiptRuleSet.data[i].Actions[j].S3Action.KmsKeyArn
									});
								}
							}
						}
					}
				}
			}

			// For Workspaces
			var describeWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

			if (describeWorkspaces) {
				if (describeWorkspaces.err || !describeWorkspaces.data) {
					helpers.addResult(results, 3,
						'Unable to query for workspaces: ' + helpers.addError(describeWorkspaces), region);
				} else {
					for (i in describeWorkspaces.data){
						if (describeWorkspaces.data[i].VolumeEncryptionKey) {
							services.push({
								serviceName: 'Workspaces',
								KMSKey: describeWorkspaces.data[i].VolumeEncryptionKey
							});
						}
					}
				}
			}

			// For S3 Buckets
			// TODO: figure out the region
			var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', 'us-east-1']);

			if (listBuckets) {
				if (listBuckets.err || !listBuckets.data) {
					helpers.addResult(results, 3,
						'Unable to query for S3 buckets: ' + helpers.addError(listBuckets), 'us-east-1');
				} else {
					for (i in listBuckets.data) {
						var bucket = listBuckets.data[i];

						if (bucket.Name) {
							var getBucketEncryption = helpers.addSource(cache, source,
							    ['s3', 'getBucketEncryption', 'us-east-1', bucket.Name]);

							if (getBucketEncryption) {
								if (getBucketEncryption.err || !getBucketEncryption.data) {
									helpers.addResult(results, 3,
										'Unable to query for S3 bucket encryption status for bucket ' +
										bucket.Name + ': ' + helpers.addError(getBucketEncryption), 'us-east-1');
								} else {
									for (j in getBucketEncryption.data){
										if (getBucketEncryption.data[j].Rules) {
											for (k in getBucketEncryption.data[j].Rules){
												if (getBucketEncryption.data[j].Rules[k].ApplyServerSideEncryptionByDefault &&
													getBucketEncryption.data[j].Rules[k].ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
												services.push({
													serviceName: 'S3',
													KMSKey: getBucketEncryption.data[j].Rules[k].ApplyServerSideEncryptionByDefault.KMSMasterKeyID
												});
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// Loop through KMS keys

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