var async = require('async');
var helpers = require('../../../helpers/aws');

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
    compliance: {
        pci: 'PCI requires vendor defaults to be changed. While KMS keys ' +
             'do not fall into the same category as vendor-default ' +
             'passwords, it is still strongly encouraged to use a ' +
             'customer-provided CMK rather than the default KMS key.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
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
                    for (var i in describeTrails.data){
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
                    for (var j in describeVolumes.data){            
                        if (describeVolumes.data[j].KmsKeyId) {
                            services.push({
                                serviceName: 'EBS',
                                resource: 'arn:aws:ec2:' + region + ':' + accountId + ':volume/' + describeVolumes.data[j].VolumeId,
                                KMSKey: describeVolumes.data[j].KmsKeyId
                            });
                        }
                    }
                }
            }    

            // For ElasticTranscoder
            if (region in regions.elastictranscoder) {
                var listPipelines = helpers.addSource(cache, source, ['elastictranscoder', 'listPipelines', region]);

                if (listPipelines) {
                    if (listPipelines.err || !listPipelines.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for ElasticTranscoder pipelines: ' + helpers.addError(listPipelines), region);
                    } else {
                        for (var k in listPipelines.data){
                            if (listPipelines.data[k].AwsKmsKeyArn) {
                                services.push({
                                    serviceName: 'ElasticTranscoder',
                                    resource: listPipelines.data[k].Arn,
                                    KMSKey: listPipelines.data[k].AwsKmsKeyArn
                                });
                            }
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
                    for (var l in describeDBInstances.data){
                        if(describeDBInstances.data[l].StorageEncrypted &&
                            describeDBInstances.data[l].KmsKeyId){
                            services.push({
                                serviceName: 'RDS',
                                resource: describeDBInstances.data[l].DBInstanceArn,
                                KMSKey: describeDBInstances.data[l].KmsKeyId
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
                    for (var m in describeClusters.data){
                        if(describeClusters.data[m].KmsKeyId){
                            services.push({
                                serviceName: 'Redshift',
                                resource: 'arn:aws:redshift:' + region + ':' + accountId + ':cluster:' + describeClusters.data[m].ClusterIdentifier,
                                KMSKey: describeClusters.data[m].KmsKeyId
                            });
                        }
                    }
                }
            }

            // For SES
            if (region in regions.ses) {
                var describeActiveReceiptRuleSet = helpers.addSource(cache, source, ['ses', 'describeActiveReceiptRuleSet', region]);

                if (describeActiveReceiptRuleSet) {
                    if (describeActiveReceiptRuleSet.err) {
                        helpers.addResult(results, 3,
                            'Unable to query for SES: ' + helpers.addError(describeActiveReceiptRuleSet), region);
                    } else if (describeActiveReceiptRuleSet.data) {
                        for (var n in describeActiveReceiptRuleSet.data){
                            if (describeActiveReceiptRuleSet.data[n].Actions) {
                                for (var o in describeActiveReceiptRuleSet.data[n].Actions){
                                    if (describeActiveReceiptRuleSet.data[n].Actions[o].S3Action &&
                                        describeActiveReceiptRuleSet.data[n].Actions[o].S3Action.KmsKeyArn) {
                                        services.push({
                                            serviceName: 'SES',
                                            resource: 'SES ruleset',
                                            KMSKey: describeActiveReceiptRuleSet.data[n].Actions[o].S3Action.KmsKeyArn
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // For Workspaces
            if (region in regions.workspaces) {
                var describeWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

                if (describeWorkspaces) {
                    if (describeWorkspaces.err || !describeWorkspaces.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for workspaces: ' + helpers.addError(describeWorkspaces), region);
                    } else {
                        for (var p in describeWorkspaces.data){
                            if (describeWorkspaces.data[p].VolumeEncryptionKey) {
                                services.push({
                                    serviceName: 'Workspaces',
                                    resource: 'arn:aws:workspaces:' + region + ':' + accountId + ':workspace/' + describeWorkspaces.data[p].WorkspaceId,
                                    KMSKey: describeWorkspaces.data[p].VolumeEncryptionKey
                                });
                            }
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
                    for (var q in listFunctions.data){
                        if (listFunctions.data[q].KMSKeyArn) {
                            services.push({
                                serviceName: 'Lambda',
                                resource: listFunctions.data[q].FunctionArn,
                                KMSKey: listFunctions.data[q].KMSKeyArn
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
                    for (var r in describeLogGroups.data){
                        if (describeLogGroups.data[r].kmsKeyId) {
                            services.push({
                                serviceName: 'CloudWatchLogs',
                                resource: describeLogGroups.data[r].arn,
                                KMSKey: describeLogGroups.data[r].kmsKeyId
                            });
                        }
                    }
                }
            }

            // For EFS
            if (region in regions.efs) {
                var describeFileSystems = helpers.addSource(cache, source, ['efs', 'describeFileSystems', region]);

                if (describeFileSystems) {
                    if (describeFileSystems.err || !describeFileSystems.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
                    } else {
                        for (var s in describeFileSystems.data){
                            if (describeFileSystems.data[s].KmsKeyId) {
                                services.push({
                                    serviceName: 'EFS',
                                    resource: 'arn:aws:elasticfilesystem:' + region + ':' + accountId + ':file-system/' + describeFileSystems.data[s].FileSystemId,
                                    KMSKey: describeFileSystems.data[s].KmsKeyId
                                });
                            }
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
                        for (var t in listBuckets.data) {
                            var bucket = listBuckets.data[t];

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
                                        for (var u in getBucketEncryption.data){
                                            if (getBucketEncryption.data[u].Rules) {
                                                for (var v in getBucketEncryption.data[u].Rules){
                                                    if (getBucketEncryption.data[u].Rules[v].ApplyServerSideEncryptionByDefault &&
                                                        getBucketEncryption.data[u].Rules[v].ApplyServerSideEncryptionByDefault.KMSMasterKeyID) {
                                                        services.push({
                                                            serviceName: 'S3',
                                                            resource: 'arn:aws:s3:::' + bucket.Name,
                                                            KMSKey: getBucketEncryption.data[u].Rules[v].ApplyServerSideEncryptionByDefault.KMSMasterKeyID
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
                for (var w in describeKey.data){
                    keysInfo.push({
                        keyId: describeKey.data[w].KeyId,
                        Desc: describeKey.data[w].Description
                    });
                }

                var defSTR = 'Default master key (.*)';
                
                for (var x in keysInfo){
                    if (keysInfo[x].Desc.match(defSTR)){
                        defaultKeys.push(keysInfo[x].keyId);
                    }
                }
                
                kcb();
            }, function(){
                var reg = 0;
                for (var y in defaultKeys){
                    for (var z in services){
                        if (services[z].KMSKey.indexOf(defaultKeys[y]) > -1){
                            reg++;
                            helpers.addResult(results, 2, 'Default KMS key: ' + defaultKeys[y] + ' in use with: ' + services[z].serviceName + ' resource: ' + services[z].resource, region, services[z].KMSKey);
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