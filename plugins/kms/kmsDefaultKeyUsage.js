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
		   'Workspaces:describeWorkspaces', 'Lambda:listFunctions', 'CloudWatchLogs:describeLogGroups',
		   'EFS:describeFileSystems', 'STS:getCallerIdentity'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		var acctRegion = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
		var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.kms, function(region, rcb) {
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
								resource: describeTrails.data[i].TrailARN,
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
								resource: 'arn:aws:ec2:' + region + ':' + accountId + ':volume/' + describeVolumes.data[i].VolumeId,
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
								resource: listPipelines.data[i].Arn,
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
								resource: describeDBInstances.data[i].DBInstanceArn,
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
								resource: 'arn:aws:redshift:' + region + ':' + accountId + ':cluster:' + describeClusters.data[i].ClusterIdentifier,
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
										resource: 'SES ruleset',
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
								resource: 'arn:aws:workspaces:' + region + ':' + accountId + ':workspace/' + describeWorkspaces.data[i].WorkspaceId,
								KMSKey: describeWorkspaces.data[i].VolumeEncryptionKey
							});
						}
					}
				}
			}

			// For Lambda
			var listFunctions = helpers.addSource(cache, source, ['lambda', 'listFunctions', region]);

			if (listFunctions) {
				if (listFunctions.err || !listFunctions.data) {
					helpers.addResult(results, 3,
						'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
				} else {
					for (i in listFunctions.data){
						if (listFunctions.data[i].KMSKeyArn) {
							services.push({
								serviceName: 'Lambda',
								resource: listFunctions.data[i].FunctionArn,
								KMSKey: listFunctions.data[i].KMSKeyArn
							});
						}
					}
				}
			}

			// For CloudWatch Logs
			var describeLogGroups = helpers.addSource(cache, source, ['cloudwatchlogs', 'describeLogGroups', region]);

			if (describeLogGroups) {
				if (describeLogGroups.err || !describeLogGroups.data) {
					helpers.addResult(results, 3,
						'Unable to query for CloudWatch Logs groups: ' + helpers.addError(describeLogGroups), region);
				} else {
					for (i in describeLogGroups.data){
						if (describeLogGroups.data[i].kmsKeyId) {
							services.push({
								serviceName: 'CloudWatchLogs',
								resource: describeLogGroups.data[i].arn,
								KMSKey: describeLogGroups.data[i].kmsKeyId
							});
						}
					}
				}
			}

			// For EFS
			var describeFileSystems = helpers.addSource(cache, source, ['efs', 'describeFileSystems', region]);

			if (describeFileSystems) {
				if (describeFileSystems.err || !describeFileSystems.data) {
					helpers.addResult(results, 3,
						'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
				} else {
					for (i in describeFileSystems.data){
						if (describeFileSystems.data[i].KmsKeyId) {
							services.push({
								serviceName: 'EFS',
								resource: 'arn:aws:elasticfilesystem:' + region + ':' + accountId + ':file-system/' + describeFileSystems.data[i].FileSystemId,
								KMSKey: describeFileSystems.data[i].KmsKeyId
							});
						}
					}
				}
			}

			// For S3 Buckets
			if (region === 'us-east-1') {
				var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

				if (listBuckets) {
					if (listBuckets.err || !listBuckets.data) {
						helpers.addResult(results, 3,
							'Unable to query for S3 buckets: ' + helpers.addError(listBuckets), region);
					} else {
						for (i in listBuckets.data) {
							var bucket = listBuckets.data[i];

							if (bucket.Name) {
								var getBucketEncryption = helpers.addSource(cache, source,
								    ['s3', 'getBucketEncryption', region, bucket.Name]);

								if (getBucketEncryption) {
									if (getBucketEncryption.err || !getBucketEncryption.data) {
										var s3Err = helpers.addError(getBucketEncryption);
										if (s3Err !== 'The server side encryption configuration was not found') {
											helpers.addResult(results, 3,
												'Unable to query for S3 bucket encryption status for bucket ' +
												bucket.Name + ': ' + s3Err, region);
										}
									} else {
										for (j in getBucketEncryption.data){
											if (getBucketEncryption.data[j].Rules) {
												for (k in getBucketEncryption.data[j].Rules){
													if (getBucketEncryption.data[j].Rules[k].ApplyServerSideEncryptionByDefault &&
														getBucketEncryption.data[j].Rules[k].ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
													services.push({
														serviceName: 'S3',
														resource: 'arn:aws:s3:::' + bucket.Name,
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
			}

			// Loop through KMS keys
			var defaultKeys = [];

            async.each(listKeys.data, function(key, kcb){
				// Describe the KMS keys
				var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

				if (!describeKey || describeKey.err || !describeKey.data) {
					helpers.addResult(results, 3,
						'Unable to query for KMS key: ' + key.KeyId + ': ' + helpers.addError(describeKey), region);
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
				
				for (i in keysInfo){
					if (keysInfo[i].Desc.match(defSTR)){
						defaultKeys.push(keysInfo[i].keyId);
					}
                }
                
				kcb();
			}, function(){
                var reg = 0;
                for (i in defaultKeys){
                    for (j in services){
                        if (services[j].KMSKey.indexOf(defaultKeys[i]) > -1){
                            reg++;
                            helpers.addResult(results, 2, 'Default KMS key: ' + defaultKeys[i] + ' in use with: ' + services[j].serviceName + ' resource: ' + services[j].resource, region, services[j].KMSKey);
                        }
                    }
                }

                if (!reg) helpers.addResult(results, 0, 'No default KMS keys found in use', region);
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};