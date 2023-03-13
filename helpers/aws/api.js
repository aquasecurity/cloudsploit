var globalServices = [
    'S3',
    'IAM',
    'CloudFront',
    'Route53',
    'Route53Domains',
    'WAFRegional',
    'WAF'
];

var integrationSendLast = [
    'EC2'
];

/*
 enabled: send integration is enable or not
 isSingleSource: whether resource is single source or not

----------Bridge Side Data----------
 BridgeServiceName: it should be the api service name which we are storing in json file in s3 collection bucket.
 BridgeCall: it should be the api call which we are storing in json file in s3 collection bucket.
 BridgePluginCategoryName: it should be equivalent to Plugin Category Name.
 BridgeProvider: it should be the cloud provider
                 Eg. 'aws', 'Azure', 'Google'

 BridgeArnIdentifier: it should be the key of the arn field data which we are storing in json file in s3 collection bucket.
                      Eg. 'TrailARN'

 BridgeIdTemplate:  this should be the template for creating the resource id.
                    supported values: name, region, cloudAccount, project, id
                    Eg. "arn:aws:cloudtrail:{region}:{cloudAccount}:trail/{name}"

 Note: If there is an arn identifier then no need to pass the arn template otherwise we have to pass the template.

 BridgeResourceType: this should be type of the resource, fetch it from the arn.
                     Eg. 'trail'

 BridgeResourceNameIdentifier: it should be the key of resource name/id data which we are storing in json file in  s3 collection bucket.
                               Eg. 'Name' or 'Id'

 Note: if there is no name then we have to pass the id.

 BridgeExecutionService: it should be equivalent to service name which we are sending from executor in payload data.
 BridgeCollectionService: it should be equivalent to service name which we are sending from collector in payload data.
 DataIdentifier: it should be the parent key field of data which we want to collect in json file in s3 collection bucket.

----------Processor Side Data----------
These fields should be according to the user and product manager, what they want to show in Inventory UI.
 InvAsset: 'CloudTrail'
 InvService: 'CloudTrail'
 InvResourceCategory: 'cloud_resources'
 InvResourceType: 'CloudTrail'

 Note: For specific category add the category name otherwise it should be 'cloud_resource'

 Take the reference from the below map
*/

// Note: In Below service map add only single source resources.
// and service name should be plugin category.

var serviceMap = {
    'CloudTrail':
        {
            enabled: true, isSingleSource: true, InvAsset: 'CloudTrail', InvService: 'CloudTrail',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'CloudTrail', BridgeServiceName: 'cloudtrail',
            BridgePluginCategoryName: 'CloudTrail', BridgeProvider: 'aws', BridgeCall: 'describeTrails',
            BridgeArnIdentifier: 'TrailARN', BridgeIdTemplate: '', BridgeResourceType: 'trail',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'CloudTrail',
            BridgeCollectionService: 'cloudtrail', DataIdentifier: 'data',
        },
    'Athena':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'athena',
            InvResourceCategory: 'database', InvResourceType: 'athena_instance', BridgeServiceName: 'athena',
            BridgePluginCategoryName: 'Athena', BridgeProvider: 'aws', BridgeCall: 'listWorkGroups',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'arn:aws:athena:{region}:{cloudAccount}:workgroup/{name}', BridgeResourceType: 'workgroup',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'Athena',
            BridgeCollectionService: 'athena', DataIdentifier: 'data',
        },
    'Timestream':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'timestreamwrite',
            InvResourceCategory: 'database', InvResourceType: 'timestreamwrite_instance', BridgeServiceName: 'timestreamwrite',
            BridgePluginCategoryName: 'Timestream', BridgeProvider: 'aws', BridgeCall: 'listDatabases',
            BridgeArnIdentifier: 'Arn', BridgeIdTemplate: '', BridgeResourceType: 'database',
            BridgeResourceNameIdentifier: 'DatabaseName', BridgeExecutionService: 'Timestream',
            BridgeCollectionService: 'timestreamwrite', DataIdentifier: 'data',
        },
    'Redshift':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'redshift',
            InvResourceCategory: 'database', InvResourceType: 'redshift_instance', BridgeServiceName: 'redshift',
            BridgePluginCategoryName: 'Redshift', BridgeProvider: 'aws', BridgeCall: 'describeClusters',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'arn:aws:redshift:{region}:{cloudAccount}:cluster:{name}',
            BridgeResourceType: 'cluster', BridgeResourceNameIdentifier: 'ClusterIdentifier',
            BridgeExecutionService: 'Redshift', BridgeCollectionService: 'redshift', DataIdentifier: 'data',
        },
    'DocumentDB':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'docdb',
            InvResourceCategory: 'database', InvResourceType: 'documentdb_instance', BridgeServiceName: 'docdb',
            BridgePluginCategoryName: 'DocumentDB', BridgeProvider: 'aws', BridgeCall: 'describeDBClusters',
            BridgeArnIdentifier: 'DBClusterArn', BridgeIdTemplate: '', BridgeResourceType: 'cluster',
            BridgeResourceNameIdentifier: 'DBClusterIdentifier', BridgeExecutionService: 'DocumentDB',
            BridgeCollectionService: 'docdb', DataIdentifier: 'data',
        },
    'Neptune':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'neptune',
            InvResourceCategory: 'database', InvResourceType: 'neptune_instance', BridgeServiceName: 'neptune',
            BridgePluginCategoryName: 'Neptune', BridgeProvider: 'aws', BridgeCall: 'describeDBClusters',
            BridgeArnIdentifier: 'DBClusterArn', BridgeIdTemplate: '', BridgeResourceType: 'cluster',
            BridgeResourceNameIdentifier: 'DBClusterIdentifier', BridgeExecutionService: 'Neptune',
            BridgeCollectionService: 'neptune', DataIdentifier: 'data',
        },
    'ElastiCache':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'elasticache',
            InvResourceCategory: 'database', InvResourceType: 'elasticache_instance', BridgeServiceName: 'elasticache',
            BridgePluginCategoryName: 'ElastiCache', BridgeProvider: 'aws', BridgeCall: 'describeCacheClusters',
            BridgeArnIdentifier: 'ARN', BridgeIdTemplate: '', BridgeResourceType: 'cluster',
            BridgeResourceNameIdentifier: 'CacheClusterId', BridgeExecutionService: 'ElastiCache',
            BridgeCollectionService: 'elasticache', DataIdentifier: 'data',
        },
    'MemoryDB':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'memorydb',
            InvResourceCategory: 'database', InvResourceType: 'memorydb_instance', BridgeServiceName: 'memorydb',
            BridgePluginCategoryName: 'MemoryDB', BridgeProvider: 'aws', BridgeCall: 'describeClusters',
            BridgeArnIdentifier: 'ARN', BridgeIdTemplate: '', BridgeResourceType: 'cluster',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'MemoryDB',
            BridgeCollectionService: 'memorydb', DataIdentifier: 'data',
        },
    'Kendra':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'kendra',
            InvResourceCategory: 'database', InvResourceType: 'kendra_instance', BridgeServiceName: 'kendra',
            BridgePluginCategoryName: 'Kendra', BridgeProvider: 'aws', BridgeCall: 'listIndices',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'arn:aws:kendra:{region}:{cloudAccount}:index/{name}',
            BridgeResourceType: 'index', BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'Kendra',
            BridgeCollectionService: 'kendra', DataIdentifier: 'data',
        },
    'ES':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'elasticsearch',
            InvResourceCategory: 'database', InvResourceType: 'elasticsearch_instance', BridgeServiceName: 'es',
            BridgePluginCategoryName: 'ES', BridgeProvider: 'aws', BridgeCall: 'describeElasticsearchDomain',
            BridgeArnIdentifier: 'ARN', BridgeIdTemplate: '', BridgeResourceType: 'domain',
            BridgeResourceNameIdentifier: 'DomainName', BridgeExecutionService: 'ES',
            BridgeCollectionService: 'es', DataIdentifier: 'DomainStatus',
        },
    'QLDB':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'qldb',
            InvResourceCategory: 'database', InvResourceType: 'qldb_instance', BridgeServiceName: 'qldb',
            BridgePluginCategoryName: 'QLDB', BridgeProvider: 'aws', BridgeCall: 'describeLedger',
            BridgeArnIdentifier: 'Arn', BridgeIdTemplate: '', BridgeResourceType: 'ledger',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'QLDB',
            BridgeCollectionService: 'qldb', DataIdentifier: 'data',
        },
    'DynamoDB':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'dynamodb',
            InvResourceCategory: 'database', InvResourceType: 'dynamodb_instance', BridgeServiceName: 'dynamodb',
            BridgePluginCategoryName: 'DynamoDB', BridgeProvider: 'aws', BridgeCall: 'describeTable',
            BridgeArnIdentifier: 'TableArn', BridgeIdTemplate: '', BridgeResourceType: 'table',
            BridgeResourceNameIdentifier: 'TableName', BridgeExecutionService: 'DynamoDB',
            BridgeCollectionService: 'dynamodb', DataIdentifier: 'Table',
        },
    'Backup':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'backup',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'backup_instance', BridgeServiceName: 'backup',
            BridgePluginCategoryName: 'Backup', BridgeProvider: 'aws', BridgeCall: 'listBackupVaults',
            BridgeArnIdentifier: 'BackupVaultArn', BridgeIdTemplate: '', BridgeResourceType: 'backup-vault',
            BridgeResourceNameIdentifier: 'BackupVaultName', BridgeExecutionService: 'Backup',
            BridgeCollectionService: 'backup', DataIdentifier: 'data',
        },
    'EFS':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'efs',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'efs_instance', BridgeServiceName: 'efs',
            BridgePluginCategoryName: 'EFS', BridgeProvider: 'aws', BridgeCall: 'describeFileSystems',
            BridgeArnIdentifier: 'FileSystemArn', BridgeIdTemplate: '', BridgeResourceType: 'file-system',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'EFS',
            BridgeCollectionService: 'efs', DataIdentifier: 'data',
        },
    'Glacier':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'glacier',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'glacier_instance', BridgeServiceName: 'glacier',
            BridgePluginCategoryName: 'Glacier', BridgeProvider: 'aws', BridgeCall: 'listVaults',
            BridgeArnIdentifier: 'VaultARN', BridgeIdTemplate: '', BridgeResourceType: 'vaults',
            BridgeResourceNameIdentifier: 'VaultName', BridgeExecutionService: 'Glacier',
            BridgeCollectionService: 'glacier', DataIdentifier: 'data',
        },
    'KMS':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'kms',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'kms_instance', BridgeServiceName: 'kms',
            BridgePluginCategoryName: 'KMS', BridgeProvider: 'aws', BridgeCall: 'describeKey',
            BridgeArnIdentifier: 'Arn', BridgeIdTemplate: '', BridgeResourceType: 'key',
            BridgeResourceNameIdentifier: 'KeyId', BridgeExecutionService: 'KMS',
            BridgeCollectionService: 'kms', DataIdentifier: 'KeyMetadata',
        },
    'Secrets Manager':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'secretsmanager',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'secretsmanager_instance',
            BridgeServiceName: 'secretsmanager', BridgePluginCategoryName: 'Secrets Manager', BridgeProvider: 'aws',
            BridgeCall: 'listSecrets', BridgeArnIdentifier: 'ARN', BridgeIdTemplate: '', BridgeResourceType: 'secret',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'Secrets Manager',
            BridgeCollectionService: 'secretsmanager', DataIdentifier: 'data',
        },
    'CloudWatchLogs':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'cloudwatchlogs',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'cloudwatchlogs_instance',
            BridgeServiceName: 'cloudwatchlogs', BridgePluginCategoryName: 'CloudWatchLogs', BridgeProvider: 'aws',
            BridgeCall: 'describeLogGroups', BridgeArnIdentifier: 'arn', BridgeIdTemplate: '', BridgeResourceType: 'log-group',
            BridgeResourceNameIdentifier: 'logGroupName', BridgeExecutionService: 'CloudWatchLogs',
            BridgeCollectionService: 'cloudwatchlogs', DataIdentifier: 'data',
        },
    'EventBridge':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'eventbridge',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'eventbridge_instance',
            BridgeServiceName: 'eventbridge', BridgePluginCategoryName: 'EventBridge', BridgeProvider: 'aws',
            BridgeCall: 'listRules', BridgeArnIdentifier: 'Arn', BridgeIdTemplate: '', BridgeResourceType: 'event-bus',
            BridgeResourceNameIdentifier: 'Name', BridgeExecutionService: 'EventBridge',
            BridgeCollectionService: 'eventbridge', DataIdentifier: 'data',
        },
    'App Mesh':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'appmesh',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'app_mesh',
            BridgeServiceName: 'appmesh', BridgePluginCategoryName: 'App Mesh', BridgeProvider: 'aws',
            BridgeCall: 'listMeshes', BridgeArnIdentifier: 'arn', BridgeIdTemplate: '', BridgeResourceType: 'mesh',
            BridgeResourceNameIdentifier: 'meshName', BridgeExecutionService: 'App Mesh',
            BridgeCollectionService: 'appmesh', DataIdentifier: 'data',
        },
    'App Runner':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'apprunner',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'app_runner',
            BridgeServiceName: 'apprunner', BridgePluginCategoryName: 'App Runner', BridgeProvider: 'aws',
            BridgeCall: 'listServices', BridgeArnIdentifier: 'ServiceArn', BridgeIdTemplate: '', BridgeResourceType: 'service',
            BridgeResourceNameIdentifier: 'ServiceName', BridgeExecutionService: 'App Runner',
            BridgeCollectionService: 'apprunner', DataIdentifier: 'data',
        },
    'AutoScaling':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'autoscaling',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'auto_scaling',
            BridgeServiceName: 'autoscaling', BridgePluginCategoryName: 'AutoScaling', BridgeProvider: 'aws',
            BridgeCall: 'describeAutoScalingGroups', BridgeArnIdentifier: 'AutoScalingGroupARN', BridgeIdTemplate: '',
            BridgeResourceType: 'autoScalingGroup', BridgeResourceNameIdentifier: 'AutoScalingGroupName',
            BridgeExecutionService: 'AutoScaling', BridgeCollectionService: 'autoscaling', DataIdentifier: 'data',
        },
    'IAM':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'accessanalyzer',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'access_analyzer',
            BridgeServiceName: 'accessanalyzer', BridgePluginCategoryName: 'IAM', BridgeProvider: 'aws',
            BridgeCall: 'listAnalyzers', BridgeArnIdentifier: 'arn', BridgeIdTemplate: '',
            BridgeResourceType: 'analyzer', BridgeResourceNameIdentifier: 'name',
            BridgeExecutionService: 'IAM', BridgeCollectionService: 'accessanalyzer', DataIdentifier: 'data',
        },
    'EMR':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'emr',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'emr_instance',
            BridgeServiceName: 'emr', BridgePluginCategoryName: 'EMR', BridgeProvider: 'aws',
            BridgeCall: 'listClusters', BridgeArnIdentifier: 'ClusterArn', BridgeIdTemplate: '',
            BridgeResourceType: 'cluster', BridgeResourceNameIdentifier: 'Name',
            BridgeExecutionService: 'EMR', BridgeCollectionService: 'emr', DataIdentifier: 'data',
        },
    'CodeArtifact':
        {
            enabled: true, isSingleSource: true, InvAsset: 'instance', InvService: 'codeArtifact',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'codeArtifact',
            BridgeServiceName: 'codeartifact', BridgePluginCategoryName: 'CodeArtifact', BridgeProvider: 'aws',
            BridgeCall: 'listDomains', BridgeArnIdentifier: 'arn', BridgeIdTemplate: '', BridgeResourceType: 'domain',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'CodeArtifact',
            BridgeCollectionService: 'codeartifact', DataIdentifier: 'data',
        },
    'CloudFormation':
        {
            enabled: true, isSingleSource: true, InvAsset: 'cloudFormation', InvService: 'cloudformation',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'cloudformation',
            BridgeServiceName: 'cloudformation', BridgePluginCategoryName: 'CloudFormation', BridgeProvider: 'aws',
            BridgeCall: 'listStacks', BridgeArnIdentifier: 'StackId', BridgeIdTemplate: '', BridgeResourceType: 'stack',
            BridgeResourceNameIdentifier: 'StackName', BridgeExecutionService: 'CloudFormation',
            BridgeCollectionService: 'cloudformation', DataIdentifier: 'data',
        },
    'CodeBuild':
        {
            enabled: true, isSingleSource: true, InvAsset: 'codeBuild', InvService: 'codeBuild',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'CodeBuild',
            BridgeServiceName: 'codebuild', BridgePluginCategoryName: 'CodeBuild', BridgeProvider: 'aws',
            BridgeCall: 'batchGetProjects', BridgeArnIdentifier: 'arn', BridgeIdTemplate: '', BridgeResourceType: 'project',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'CodeBuild',
            BridgeCollectionService: 'codebuild', DataIdentifier: 'projects',
        },
};

var calls = {
    AccessAnalyzer: {
        listAnalyzers: {
            property: 'analyzers',
            paginate: 'NextToken'
        }
    },
    ACM: {
        listCertificates: {
            property: 'CertificateSummaryList',
            paginate: 'NextToken'
        }
    },
    APIGateway: {
        getRestApis: {
            property: 'items',
            paginate: 'NextToken'
        },
        getDomainNames: {
            property: 'items',
            paginate: 'NextToken'
        }
    },
    AppConfig: {
        listApplications: {
            property: 'Items',
            paginate: 'NextToken'
        }
    },
    AppMesh: {
        listMeshes: {
            property: 'meshes',
            paginate: 'nextToken'
        }
    },
    AppRunner: {
        listServices: {
            property: 'ServiceSummaryList',
            paginate: 'NextToken'
        }
    },
    Appflow: {
        listFlows: {
            property: 'flows',
            paginate: 'nextToken'
        }
    },
    Athena: {
        listWorkGroups: {
            property: 'WorkGroups',
            paginate: 'NextToken',
            params: {
                MaxResults: 50
            }
        }
    },
    AuditManager: {
        getSettings: {
            property: 'settings',
            params: {
                attribute: 'ALL'
            }
        }
    },
    AutoScaling: {
        describeAutoScalingGroups: {
            property: 'AutoScalingGroups',
            paginate: 'NextToken',
            params: {
                MaxRecords: 100
            }
        },
        describeLaunchConfigurations: {
            property: 'LaunchConfigurations',
            paginate: 'NextToken',
            params: {
                MaxRecords: 100
            }
        }
    },
    Backup: {
        listBackupVaults: {
            property: 'BackupVaultList',
            paginate: 'NextToken',
        },
        describeRegionSettings: {
            property: 'ResourceTypeOptInPreference',
        },
        listBackupPlans: {
            property: 'BackupPlansList',
            paginate: 'NextToken'
        }
    },
    CloudFormation: {
        listStacks: {
            property: 'StackSummaries',
            params: {
                'StackStatusFilter': [
                    'CREATE_IN_PROGRESS',
                    'CREATE_COMPLETE',
                    'ROLLBACK_IN_PROGRESS',
                    'ROLLBACK_FAILED',
                    'ROLLBACK_COMPLETE',
                    'DELETE_FAILED',
                    'UPDATE_IN_PROGRESS',
                    'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_COMPLETE',
                    'UPDATE_ROLLBACK_IN_PROGRESS',
                    'UPDATE_ROLLBACK_FAILED',
                    'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_ROLLBACK_COMPLETE',
                    'REVIEW_IN_PROGRESS',
                    'IMPORT_IN_PROGRESS',
                    'IMPORT_COMPLETE',
                    'IMPORT_ROLLBACK_IN_PROGRESS',
                    'IMPORT_ROLLBACK_FAILED',
                    'IMPORT_ROLLBACK_COMPLETE',
                ]
            }
        },
        describeStacks: {
            property: 'Stacks',
            paginate: 'NextToken',
        }
    },
    CloudFront: {
        // TODO: Pagination is using an older format
        listDistributions: {
            property: 'DistributionList',
            secondProperty: 'Items'
        }
    },
    CloudTrail: {
        describeTrails: {
            property: 'trailList'
        }
    },
    CloudWatch: {
        describeAlarms: {
            property: 'MetricAlarms',
            paginate: 'NextToken'
        }
    },
    CloudWatchLogs: {
        describeLogGroups: {
            property: 'logGroups',
            paginate: 'nextToken',
            params: {
                limit: 50
            },
            rateLimit: 500
        },
        describeMetricFilters: {
            property: 'metricFilters',
            paginate: 'nextToken',
            params: {
                limit: 50 // The max available
            }
        }
    },
    CodeArtifact: {
        listDomains: {
            property: 'domains',
            paginate: 'nextToken'
        }
    },
    CodeStar: {
        listProjects: {
            property: 'projects',
            paginate: 'nextToken'
        }
    },
    CodeBuild: {
        listProjects: {
            property: 'projects',
            paginate: 'nextToken'
        }
    },
    CognitoIdentityServiceProvider: {
        listUserPools: {
            property: 'UserPools',
            paginate: 'NextToken',
            params: {
                MaxResults: 60
            }
        }
    },
    CodePipeline: {
        listPipelines: {
            property: 'pipelines',
            paginate: 'nextToken'
        }
    },
    ComputeOptimizer: {
        getRecommendationSummaries : {
            property: 'recommendationSummaries',
            paginate: 'nextToken'
        }
    },
    Comprehend: {
        listEntitiesDetectionJobs: {
            property: 'EntitiesDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listDocumentClassificationJobs: {
            property: 'DocumentClassificationJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listDominantLanguageDetectionJobs: {
            property: 'DominantLanguageDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listKeyPhrasesDetectionJobs: {
            property: 'KeyPhrasesDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listSentimentDetectionJobs: {
            property: 'SentimentDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listTopicsDetectionJobs: {
            property: 'TopicsDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        }
    },
    Connect: {
        listInstances: {
            property: 'InstanceSummaryList',
            paginate: 'NextToken'
        }
    },
    ConfigService: {
        describeConfigurationRecorders: {
            property: 'ConfigurationRecorders'
        },
        describeConfigurationRecorderStatus: {
            property: 'ConfigurationRecordersStatus'
        },
        describeConfigRules: {
            property: 'ConfigRules',
            paginate: 'NextToken'
        },
        describeDeliveryChannels: {
            property: 'DeliveryChannels'
        },
        getDiscoveredResourceCounts: {
            property: 'resourceCounts',
            paginate: 'NextToken'
        }
    },
    CustomerProfiles: {
        listDomains: {
            property: 'Items',
            paginate: 'NextToken',
        }
    },
    DataBrew: {
        listJobs: {
            property: 'Jobs',
            paginate: 'NextToken'
        }
    },
    DevOpsGuru: {
        listNotificationChannels: {
            property: 'Channels',
            paginate: 'NextToken'
        }
    },
    DirectConnect: {
        describeDirectConnectGateways: {
            property: 'directConnectGateways',
            paginate: 'nextToken'
        }
    },
    DirectoryService: {
        describeDirectories: {
            property: 'DirectoryDescriptions',
            paginate: 'NextToken'
        }
    },
    DLM: {
        getLifecyclePolicies: {
            property: 'Policies'
        }
    },
    DMS: {
        describeReplicationInstances: {
            property: 'ReplicationInstances',
            paginate: 'Marker'
        }
    },
    DocDB: {
        describeDBClusters: {
            property: 'DBClusters',
            paginate: 'Marker',
            params: {
                Filters: [
                    {
                        Name: 'engine',
                        Values: [
                            'docdb'
                        ]
                    }
                ]
            }
        }
    },
    DynamoDB: {
        listTables: {
            property: 'TableNames',
            paginate: 'LastEvaluatedTableName',
            paginateReqProp: 'ExclusiveStartTableName'
        }
    },
    DAX: {
        describeClusters: {
            property: 'Clusters',
            paginate: 'NextToken'
        }
    },
    TimestreamWrite: {
        listDatabases: {
            property: 'Databases',
            paginate: 'NextToken'
        }
    },
    EC2: {
        describeAccountAttributes: {
            property: 'AccountAttributes'
        },
        describeSubnets: {
            property: 'Subnets',
            paginate: 'NextToken'
        },
        describeAddresses: {
            property: 'Addresses'
        },
        describeVolumes: {
            property: 'Volumes'
        },
        describeSnapshots: {
            // This call must be overridden because the
            // default call retrieves every snapshot
            // available, including public ones
            override: true
        },
        describeInstances: {
            property: 'Reservations',
            paginate: 'NextToken',
            params: {
                MaxResults: 1000,
                Filters: [
                    {
                        Name: 'instance-state-name',
                        Values: [
                            'pending',
                            'running',
                            'shutting-down',
                            'stopping',
                            'stopped'
                        ]
                    }
                ]
            }
        },
        describeSecurityGroups: {
            property: 'SecurityGroups'
        },
        describeVpcs: {
            property: 'Vpcs',
            paginate: 'NextToken'
        },
        describeFlowLogs: {
            // TODO: override bc flowlogs are not available in all regions?
            property: 'FlowLogs'
        },
        describeImages: {
            property: 'Images',
            params: {
                Owners: [
                    'self'
                ],
                Filters: [
                    {
                        Name: 'state',
                        Values: [
                            'available'
                        ]
                    }
                ]
            }
        },
        describeInternetGateways: {
            property: 'InternetGateways'
        },
        describeEgressOnlyInternetGateways: {
            property: 'EgressOnlyInternetGateways'
        },
        describeNatGateways: {
            property: 'NatGateways',
            paginate: 'NextToken',
            params: {
                Filter: [
                    {
                        Name: 'state',
                        Values: [
                            'available'
                        ]
                    }
                ]
            }
        },
        describeVpcPeeringConnections: {
            property: 'VpcPeeringConnections',
            paginate: 'NextToken',
            params: {
                Filters: [
                    {
                        Name: 'status-code',
                        Values: [
                            'pending-acceptance',
                            'provisioning',
                            'active'
                        ]
                    }
                ]
            }
        },
        describeVpnGateways: {
            property: 'VpnGateways',
            params: {
                Filters: [
                    {
                        Name: 'state',
                        Values: [
                            'available'
                        ]
                    }
                ]
            }
        },
        describeVpcEndpointServices: {
            property: 'ServiceDetails',
            paginate: 'NextToken'
        },
        describeVpcEndpoints: {
            property: 'VpcEndpoints',
            paginate: 'NextToken'
        },
        describeRouteTables: {
            property: 'RouteTables',
            paginate: 'NextToken'
        },
        describeTags: {
            property: 'Tags',
            paginate: 'NextToken',
        },
        describeNetworkInterfaces: {
            property: 'NetworkInterfaces',
            paginate: 'NextToken',
        },
        getEbsEncryptionByDefault: {
            property: 'EbsEncryptionByDefault'
        },
        getEbsDefaultKmsKeyId: {
            property: 'KmsKeyId'
        },
        describeVpnConnections: {
            property: 'VpnConnections',
            paginate: 'NextToken'
        },
        describeNetworkAcls: {
            property: 'NetworkAcls',
            paginate: 'NextToken',
        },
        describeLaunchTemplates: {
            property: 'LaunchTemplates',
            paginate: 'NextToken',
        }
    },
    ElastiCache: {
        describeCacheClusters: {
            property: 'CacheClusters',
            paginate: 'Marker'
        },
        describeReservedCacheNodes: {
            property: 'ReservedCacheNodes',
            paginate: 'Marker'
        }
    },
    ECR: {
        describeRepositories: {
            property: 'repositories',
            paginate: 'nextToken',
            params: {
                maxResults: 1000
            }
        },
        describeRegistry: {}
    },
    ECRPUBLIC: {
        describeRegistries: {
            property: 'registries',
            paginate: 'nextToken',
            params: {
                maxResults: 1000
            }
        }
    },
    EFS: {
        describeFileSystems: {
            property: 'FileSystems',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    EKS: {
        listClusters: {
            property: 'clusters',
            paginate: 'nextToken'
        }
    },
    ECS: {
        listClusters: {
            property: 'clusterArns',
            paginate: 'nextToken'
        }
    },
    ElasticBeanstalk: {
        describeEnvironments: {
            property: 'Environments',
            paginate: 'NextToken'
        }
    },
    ElasticTranscoder: {
        // TODO: Pagination via NextPageToken and PageToken
        listPipelines: {
            property: 'Pipelines',
            paginate: 'NextPageToken',
            paginateReqProp: 'PageToken'
        }
    },
    ELB: {
        describeLoadBalancers: {
            property: 'LoadBalancerDescriptions',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    ELBv2: {
        describeLoadBalancers: {
            property: 'LoadBalancers',
            paginate: 'NextMarker',
            reliesOnService: 'ec2',
            reliesOnCall: 'describeVpcs',
            paginateReqProp: 'Marker'
        },
        describeTargetGroups: {
            property: 'TargetGroups',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        },
        describeTargetHealth: {
            property: 'TargetGroups',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    EMR: {
        listClusters: {
            property: 'Clusters',
            paginate: 'Marker',
            params: {
                ClusterStates: [
                    'RUNNING','WAITING'
                ]
            }
        }
    },
    ES: {
        listDomainNames: {
            property: 'DomainNames',
        }
    },
    EventBridge: {
        listEventBuses: {
            property: 'EventBuses',
            paginate: 'NextToken',
            params:{
                Limit: 100,
            }
        },
        listRules: {
            property: 'Rules',
            paginate: 'NextToken',
        }
    },
    Finspace: {
        listEnvironments: {
            property: 'environments',
            paginate: 'nextToken'
        }
    },
    ForecastService: {
        listDatasets: {
            property: 'Datasets',
            paginate: 'NextToken'
        },
        listForecastExportJobs: {
            property: 'ForecastExportJobs',
            paginate: 'NextToken'
        }
    },
    FSx: {
        describeFileSystems: {
            property: 'FileSystems',
            paginate: 'NextToken'
        }
    },
    FraudDetector: {
        getDetectors: {
            property: 'detectors',
            paginate: 'nextToken'
        },
        getKMSEncryptionKey: {
            property: 'kmsKey'
        }
    },
    Glue: {
        getDataCatalogEncryptionSettings: {
            property: 'DataCatalogEncryptionSettings',
        },
        getSecurityConfigurations: {
            property: 'SecurityConfigurations',
            paginate: 'NextMarker'
        }
    },
    Glacier: {
        listVaults: {
            paginate: 'Marker',
            property: 'VaultList',
            params: {
                accountId: '-',
                limit: '50'
            },
        }
    },
    HealthLake: {
        listFHIRDatastores: {
            property: 'DatastorePropertiesList',
            paginate: 'NextToken'
        }
    },
    Imagebuilder: {
        listContainerRecipes: {
            property: 'containerRecipeSummaryList',
            paginate: 'nextToken'
        },
        listComponents: {
            property: 'componentVersionList',
            paginate: 'nextToken'
        },
        listImagePipelines: {
            property: 'imagePipelineList',
            paginate: 'nextToken'
        },
        listImageRecipes: {
            property: 'imageRecipeSummaryList',
            paginate: 'nextToken'
        },
        listInfrastructureConfigurations: {
            property: 'infrastructureConfigurationSummaryList',
            paginate: 'nextToken'
        }
    },
    IAM: {
        listServerCertificates: {
            property: 'ServerCertificateMetadataList',
            paginate: 'Marker'
        },
        listGroups: {
            property: 'Groups',
            paginate: 'Marker'
        },
        listUsers: {
            property: 'Users',
            paginate: 'Marker'
        },
        listRoles: {
            property: 'Roles',
            paginate: 'Marker'
        },
        listPolicies: {
            property: 'Policies',
            paginate: 'Marker',
            params: {
                OnlyAttached: true // Making this false will effect IAM Support Policy plugin
            }
        },
        listVirtualMFADevices: {
            property: 'VirtualMFADevices',
            paginate: 'Marker'
        },
        getAccountPasswordPolicy: {
            property: 'PasswordPolicy'
        },
        getAccountSummary: {
            property: 'SummaryMap'
        },
        generateCredentialReport: {
            override: true
        }
    },
    IoTSiteWise: {
        describeDefaultEncryptionConfiguration: {
        }
    },
    Kinesis: {
        listStreams: {
            property: 'StreamNames'
        }
    },
    KinesisVideo: {
        listStreams: {
            property: 'StreamInfoList',
            paginate: 'NextToken',
        }
    },
    Firehose: {
        listDeliveryStreams: {
            property: 'DeliveryStreamNames'
        }
    },
    GuardDuty: {
        listDetectors: {
            property: 'DetectorIds',
            paginate: 'NextToken',
        }
    },
    Kendra: {
        listIndices: {
            property: 'IndexConfigurationSummaryItems',
            paginate: 'NextToken'
        }
    },
    KMS: {
        listKeys: {
            property: 'Keys',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker',
            params: {
                Limit: 1000
            }
        },
        listAliases: {
            property: 'Aliases',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker',
            params: {
                Limit: 100
            }
        }
    },
    Kafka: {
        listClusters: {
            property: 'ClusterInfoList',
            paginate: 'NextToken'
        }
    },
    Lambda: {
        listFunctions: {
            property: 'Functions',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    LookoutEquipment: {
        listDatasets: {
            property: 'DatasetSummaries',
            paginate: 'NextToken'
        }
    },
    Location: {
        listTrackers: {
            property: 'Entries',
            paginate: 'NextToken',
        },
        listGeofenceCollections: {
            property: 'Entries',
            paginate: 'NextToken',
        }
    },
    LookoutVision: {
        listProjects: {
            property: 'Projects',
            paginate: 'NextToken'
        }
    },
    LexModelsV2: {
        listBots: {
            property: 'botSummaries',
            paginate: 'nextToken'
        }
    },
    LookoutMetrics: {
        listAnomalyDetectors: {
            property: 'AnomalyDetectorSummaryList',
            paginate: 'NextToken'
        }
    },
    MemoryDB: {
        describeClusters: {
            property:'Clusters',
            paginate:'NextToken'
        }
    },
    ManagedBlockchain: {
        listNetworks: {
            property: 'Networks',
            paginate: 'NextToken'
        }
    },
    MQ: {
        listBrokers:{
            property:'BrokerSummaries',
            paginate:'NextToken'
        }
    },
    MWAA: {
        listEnvironments: {
            property: 'Environments',
            paginate: 'NextToken'
        }
    },
    Neptune: {
        describeDBClusters: {
            property: 'DBClusters',
            paginate: 'Marker'
        }
    },
    Organizations: {
        describeOrganization: {
            property: 'Organization',
        },
        listHandshakesForAccount: {
            property: 'Handshakes',
        },
        listAccounts: {
            property: 'Accounts',
            paginate: 'NextToken'
        },
    },
    Proton: {
        listEnvironmentTemplates: {
            property: 'templates',
            paginate: 'nextToken'
        }
    },
    QLDB: {
        listLedgers: {
            property: 'Ledgers',
            paginate: 'NextToken'
        }
    },
    RDS: {
        describeDBInstances: {
            property: 'DBInstances',
            paginate: 'Marker'
        },
        describeDBClusters: {
            property: 'DBClusters',
            paginate: 'Marker'
        },
        describeDBEngineVersions: {
            property: 'DBEngineVersions',
            paginate: 'Marker',
            default: true
        },
        describeDBSnapshots: {
            property: 'DBSnapshots',
            paginate: 'Marker'
        },
        describeDBParameterGroups: {
            property: 'DBParameterGroups',
            paginate: 'Marker'
        },
        describeDBClusterSnapshots: {
            property: 'DBClusterSnapshots',
            paginate: 'Marker'
        }
    },
    Redshift: {
        describeClusters: {
            property: 'Clusters',
            paginate: 'Marker'
        },
        describeClusterParameterGroups: {
            property: 'ParameterGroups',
            paginate: 'Marker'
        },
        describeReservedNodes: {
            property: 'ReservedNodes',
            paginate: 'Marker'
        }
    },
    ResourceGroupsTaggingAPI: {
        getTagKeys: {
            property: 'TagKeys',
            paginate: 'PaginationToken'
        },
        getResources: {
            property: 'ResourceTagMappingList',
            paginate: 'PaginationToken'
        }
    },
    Route53: {
        listHostedZones: {
            property: 'HostedZones',
            paginate: 'NextPageMarker',
            paginateReqProp: 'Marker'
        },
    },
    Route53Domains: {
        listDomains: {
            property: 'Domains',
            paginate: 'NextPageMarker',
            paginateReqProp: 'Marker'
        }
    },
    S3: {
        listBuckets: {
            property: 'Buckets'
        }
    },
    SageMaker: {
        listNotebookInstances: {
            property: 'NotebookInstances',
            paginate: 'NextToken'
        }
    },
    SecretsManager: {
        listSecrets: {
            property: 'SecretList',
            paginate: 'NextToken'
        }
    },
    ServiceQuotas: {
        listServiceQuotas: {
            property: 'Quotas',
            paginate: 'NextToken',
            params: {
                ServiceCode: 'ec2'
            },
        }
    },
    SES: {
        listIdentities: {
            property: 'Identities',
            paginate: 'NextToken',
            params: {
                IdentityType: 'Domain', // TODO: maybe don't filter these?
                MaxItems: 1000
            },
            rateLimit: 1000 // ms to rate limit between regions
        },
        describeActiveReceiptRuleSet: {
        }
    },
    Shield: {
        describeSubscription: {
            property: 'Subscription'
        },
        describeEmergencyContactSettings: {
            property: 'EmergencyContactList'
        },
        listProtections: {
            property: 'Protections'
        }
    },
    SNS: {
        listTopics: {
            property: 'Topics',
            paginate: 'NextToken'
        },
        listSubscriptions: {
            property: 'Subscriptions',
            paginate: 'NextToken'
        },
    },
    SQS: {
        listQueues: {
            property: 'QueueUrls'
        }
    },
    SSM: {
        describeInstanceInformation: {
            property: 'InstanceInformationList',
            params: {
                MaxResults: 50
            },
            paginate: 'NextToken'
        },
        describeParameters: {
            property: 'Parameters',
            params: {
                MaxResults: 50
            },
            paginate: 'NextToken'
        },
        listAssociations: {
            property: 'Associations',
            paginate: 'NextToken'
        },
        getServiceSetting: {
            property: 'ServiceSetting',
            paginate: 'NextToken',
            params: {
                SettingId: '/ssm/documents/console/public-sharing-permission'
            }
        },
        describeSessions: {
            property: 'Sessions',
            paginate: 'NextToken',
            params: {
                State: 'Active'
            }
        }
    },
    STS: {
        getCallerIdentity: {
            property: 'Account'
        }
    },
    Support: {
        describeTrustedAdvisorChecks: {
            property: 'checks',
            params: { language: 'en' },
        },
    },
    Transfer: {
        listServers: {
            property: 'Servers',
            paginate: 'NextToken',
            params: {
                MaxResults: 1000
            }
        }
    },
    Translate: {
        listTextTranslationJobs: {
            property: 'TextTranslationJobPropertiesList',
            paginate: 'NextToken'
        }
    },
    VoiceID: {
        listDomains: {
            property: 'DomainSummaries',
            paginate: 'NextToken'
        }
    },
    WAFRegional: {
        listWebACLs: {
            property: 'WebACLs',
            paginate: 'NextMarker'
        }
    },
    WAFV2: {
        listWebACLs: {
            property: 'WebACLs',
            paginate: 'NextMarker',
            params: {
                Scope: 'REGIONAL'
            }
        }
    },
    WAF: {
        listWebACLs: {
            property: 'WebACLs',
            paginate: 'NextMarker'
        }
    },
    WorkSpaces: {
        describeWorkspaces: {
            property: 'Workspaces',
            paginate: 'NextToken'
        },
        describeWorkspaceDirectories:{
            property: 'Directories',
            paginate: 'NextToken'
        },
        describeIpGroups:{
            property: 'Result',
            paginate: 'NextToken'
        },
        describeWorkspacesConnectionStatus: {
            property: 'WorkspacesConnectionStatus',
            paginate: 'NextToken'
        }
    },
    Wisdom: {
        listAssistants: {
            property: 'assistantSummaries',
            paginate: 'NextToken'
        }
    },
    XRay: {
        getEncryptionConfig: {
            property: 'EncryptionConfig'
        }
    }
};

var postcalls = [
    {
        MemoryDB: {
            sendIntegration: serviceMap['MemoryDB']
        },
        DocDB: {
            sendIntegration: serviceMap['DocumentDB']
        },
        Neptune: {
            sendIntegration:serviceMap['Neptune']
        },
        TimestreamWrite: {
            sendIntegration: serviceMap['Timestream']
        },
        EFS: {
            sendIntegration: serviceMap['EFS']
        },
        EventBridge: {
            sendIntegration: serviceMap['EventBridge']
        },
        CloudWatchLogs: {
            sendIntegration: serviceMap['CloudWatchLogs']
        },
        CodeArtifact: {
            sendIntegration: serviceMap['CodeArtifact']
        },
        ACM: {
            describeCertificate: {
                reliesOnService: 'acm',
                reliesOnCall: 'listCertificates',
                filterKey: 'CertificateArn',
                filterValue: 'CertificateArn'
            }
        },
        AccessAnalyzer: {
            listFindings: {
                reliesOnService: 'accessanalyzer',
                reliesOnCall: 'listAnalyzers',
                override: true
            },
            sendIntegration: serviceMap['IAM']
        },
        APIGateway: {
            getStages: {
                reliesOnService: 'apigateway',
                reliesOnCall: 'getRestApis',
                filterKey: 'restApiId',
                filterValue: 'id'
            },
            getResources: {
                reliesOnService: 'apigateway',
                reliesOnCall: 'getRestApis',
                filterKey: 'restApiId',
                filterValue: 'id'
            }
        },
        AppConfig: {
            listConfigurationProfiles: {
                reliesOnService: 'appconfig',
                reliesOnCall: 'listApplications',
                filterKey: 'ApplicationId',
                filterValue: 'Id'
            }
        },
        AppMesh: {
            listVirtualGateways: {
                reliesOnService: 'appmesh',
                reliesOnCall: 'listMeshes',
                filterKey: 'meshName',
                filterValue: 'meshName'
            },
            describeMesh: {
                reliesOnService: 'appmesh',
                reliesOnCall: 'listMeshes',
                filterKey: 'meshName',
                filterValue: 'meshName'
            },
            sendIntegration: serviceMap['App Mesh']
        },
        AppRunner: {
            describeService: {
                reliesOnService: 'apprunner',
                reliesOnCall: 'listServices',
                filterKey: 'ServiceArn',
                filterValue: 'ServiceArn'
            },
            sendIntegration: serviceMap['App Runner']
        },
        Appflow: {
            describeFlow: {
                reliesOnService: 'appflow',
                reliesOnCall: 'listFlows',
                filterKey: 'flowName',
                filterValue: 'flowName'
            }
        },
        Athena: {
            getWorkGroup: {
                reliesOnService: 'athena',
                reliesOnCall: 'listWorkGroups',
                filterKey: 'WorkGroup',
                filterValue: 'Name'
            },
            sendIntegration: serviceMap['Athena']
        },
        AutoScaling: {
            describeNotificationConfigurations: {
                reliesOnService: 'autoscaling',
                reliesOnCall: 'describeAutoScalingGroups',
                override: true
            },
            describeLaunchConfigurations: {
                reliesOnService: 'autoscaling',
                reliesOnCall: 'describeAutoScalingGroups',
                override: true
            },
            sendIntegration: serviceMap['AutoScaling']
        },
        Backup: {
            getBackupVaultNotifications: {
                reliesOnService: 'backup',
                reliesOnCall: 'listBackupVaults',
                filterKey: 'BackupVaultName',
                filterValue: 'BackupVaultName',
            },
            getBackupVaultAccessPolicy: {
                reliesOnService: 'backup',
                reliesOnCall: 'listBackupVaults',
                filterKey: 'BackupVaultName',
                filterValue: 'BackupVaultName',
            },
            getBackupPlan: {
                reliesOnService: 'backup',
                reliesOnCall: 'listBackupPlans',
                filterKey: 'BackupPlanId',
                filterValue: 'BackupPlanId',
            },
            sendIntegration: serviceMap['Backup']
        },
        CloudFormation: {
            describeStackEvents: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName',
                rateLimit: 100 // ms to rate limit between stacks
            },
            describeStacks: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName',
                rateLimit: 100 // ms to rate limit between stacks
            },
            sendIntegration: serviceMap['CloudFormation']
        },
        CloudFront: {
            getDistribution: {
                reliesOnService: 'cloudfront',
                reliesOnCall: 'listDistributions',
                override: true
            }
        },
        CloudTrail: {
            getTrailStatus: {
                reliesOnService: 'cloudtrail',
                reliesOnCall: 'describeTrails',
                filterKey: 'Name',
                filterValue: 'TrailARN'
            },
            listTags: {
                reliesOnService: 'cloudtrail',
                reliesOnCall: 'describeTrails',
                override: true
            },
            getEventSelectors: {
                reliesOnService: 'cloudtrail',
                reliesOnCall: 'describeTrails',
                filterKey: 'TrailName',
                filterValue: 'TrailARN'
            },
            sendIntegration: serviceMap['CloudTrail']
        },
        Imagebuilder: {
            getContainerRecipe: {
                reliesOnService: 'imagebuilder',
                reliesOnCall: 'listContainerRecipes',
                filterKey: 'containerRecipeArn',
                filterValue: 'arn'
            },
            getComponent: {
                reliesOnService: 'imagebuilder',
                reliesOnCall: 'listComponents',
                filterKey: 'componentBuildVersionArn',
                filterValue: 'arn'
            },
            getInfrastructureConfiguration: {
                reliesOnService: 'imagebuilder',
                reliesOnCall: 'listInfrastructureConfigurations',
                filterKey: 'infrastructureConfigurationArn',
                filterValue: 'arn'
            },
            getImageRecipe: {
                reliesOnService: 'imagebuilder',
                reliesOnCall: 'listImageRecipes',
                filterKey: 'imageRecipeArn',
                filterValue: 'arn'
            }
        },
        CloudWatch: {
            getEsMetricStatistics: {
                reliesOnService: 'es',
                reliesOnCall: 'listDomainNames',
                override: true,
            },
            getEcMetricStatistics: {
                reliesOnService: 'elasticache',
                reliesOnCall: 'describeCacheClusters',
                override: true,
            },
        },
        ConfigService: {
            getComplianceDetailsByConfigRule: {
                reliesOnService: 'configservice',
                reliesOnCall: 'describeConfigRules',
                filterKey: 'ConfigRuleName',
                filterValue: 'ConfigRuleName'
            }
        },
        CodeStar: {
            describeProject: {
                reliesOnService: 'codestar',
                reliesOnCall: 'listProjects',
                filterKey: 'id',
                filterValue: 'projectId'
            }
        },
        CustomerProfiles: {
            getDomain: {
                reliesOnService: 'customerprofiles',
                reliesOnCall: 'listDomains',
                filterKey: 'DomainName',
                filterValue: 'DomainName'
            }
        },
        CodeBuild: {
            batchGetProjects: {
                reliesOnService: 'codebuild',
                reliesOnCall: 'listProjects',
                override: true
            },
            sendIntegration: serviceMap['CodeBuild']
        },
        CodePipeline: {
            getPipeline: {
                reliesOnService: 'codepipeline',
                reliesOnCall: 'listPipelines',
                filterKey: 'name',
                filterValue: 'name'
            }
        },
        Connect: {
            listInstanceCallRecordingStorageConfigs: {
                reliesOnService: 'connect',
                reliesOnCall: 'listInstances',
                override: true
            },
            listInstanceMediaStreamStorageConfigs: {
                reliesOnService: 'connect',
                reliesOnCall: 'listInstances',
                override: true
            },
            listInstanceChatTranscriptStorageConfigs: {
                reliesOnService: 'connect',
                reliesOnCall: 'listInstances',
                override: true
            },
            listInstanceExportedReportStorageConfigs: {
                reliesOnService: 'connect',
                reliesOnCall: 'listInstances',
                override: true
            },
            instanceAttachmentStorageConfigs: {
                reliesOnService: 'connect',
                reliesOnCall: 'listInstances',
                override: true
            }
        },
        DynamoDB: {
            describeTable: {
                reliesOnService: 'dynamodb',
                reliesOnCall: 'listTables',
                override: true
            },
            describeContinuousBackups: {
                reliesOnService: 'dynamodb',
                reliesOnCall: 'listTables',
                override: true
            },
            listBackups: {
                reliesOnService: 'dynamodb',
                reliesOnCall: 'listTables',
                override: true
            },
            sendIntegration: serviceMap['DynamoDB']
        },
        ElastiCache: {
            describeReplicationGroups: {
                reliesOnService: 'elasticache',
                reliesOnCall: 'describeCacheClusters',
                filterKey: 'ReplicationGroupId',
                filterValue: 'ReplicationGroupId'
            },
            sendIntegration: serviceMap['ElastiCache']
        },
        ES: {
            describeElasticsearchDomain: {
                reliesOnService: 'es',
                reliesOnCall: 'listDomainNames',
                filterKey: 'DomainName',
                filterValue: 'DomainName'
            },
            sendIntegration: serviceMap['ES']
        },
        S3: {
            getBucketLogging: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketVersioning: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketAcl: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketPolicy: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketPolicyStatus: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override:true
            },
            getBucketEncryption: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketTagging: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketLocation: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getPublicAccessBlock: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketWebsite: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getObjectLockConfiguration: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketLifecycleConfiguration: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketAccelerateConfiguration: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                filterKey: 'Bucket',
                filterValue: 'Name'
            },
            headBucket: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                filterKey: 'Bucket',
                filterValue: 'Name'
            },
            listObjects: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                filterKey: 'Bucket',
                filterValue: 'Name'
            },
            sendIntegration: {
                enabled: true
            }
        },
        CognitoIdentityServiceProvider: {
            describeUserPool: {
                reliesOnService: 'cognitoidentityserviceprovider',
                reliesOnCall: 'listUserPools',
                filterKey: 'UserPoolId',
                filterValue: 'Id'
            }
        },
        EC2: {
            describeSubnets: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeVpcs',
                override: true
            },
            describeSnapshotAttribute: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeSnapshots',
                override: true
            },
            describeVpcEndpointServicePermissions: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeVpcEndpointServices',
                filterKey: 'ServiceId',
                filterValue: 'ServiceId'
            },
            describeLaunchTemplateVersions: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeLaunchTemplates',
                filterKey: 'LaunchTemplateId',
                filterValue: 'LaunchTemplateId'
            },
            sendIntegration: {
                sendLast: true,
                enabled: true,
                integrationReliesOn: {
                    serviceName: ['ELBv2', 'IAM']
                }
            }
        },
        ECR: {
            getRepositoryPolicy: {
                reliesOnService: 'ecr',
                reliesOnCall: 'describeRepositories',
                filterKey: 'repositoryName',
                filterValue: 'repositoryName'
            },
            listTagsForResource:{
                reliesOnService: 'ecr',
                reliesOnCall: 'describeRepositories',
                filterKey: 'resourceArn',
                filterValue: 'repositoryArn'
            },
            sendIntegration: {
                enabled: true
            }
        },
        ECRPUBLIC: {
            describeRepositories: {
                reliesOnService: 'ecr',
                reliesOnCall: 'describeRegistries',
                filterKey: 'registryId',
                filterValue: 'registryId'
            }
        },
        EKS: {
            describeCluster: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            },
            listNodegroups: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            }
        },
        ECS: {
            describeCluster: {
                reliesOnService: 'ecs',
                reliesOnCall: 'listClusters',
                override: true
            },
            listContainerInstances: {
                reliesOnService: 'ecs',
                reliesOnCall: 'listClusters',
                override: true
            },
            listServices: {
                reliesOnService: 'ecs',
                reliesOnCall: 'listClusters',
                override: true
            }
        },
        ElasticBeanstalk: {
            describeConfigurationSettings: {
                reliesOnService: 'elasticbeanstalk',
                reliesOnCall: 'describeEnvironments',
                override: true
            }
        },
        ElasticTranscoder: {
            listJobsByPipeline:  {
                reliesOnService: 'elastictranscoder',
                reliesOnCall: 'listPipelines',
                filterKey: 'PipelineId',
                filterValue: 'Id'
            }
        },
        ELB: {
            describeLoadBalancerPolicies: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeLoadBalancerAttributes: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeTags: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            }
        },
        ELBv2: {
            describeTargetHealth: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeTargetGroups',
                filterKey: 'TargetGroupArn',
                filterValue: 'TargetGroupArn'
            },
            describeLoadBalancerAttributes: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeListeners: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeTargetGroups: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeTargetGroupAttributes: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeTargetGroups',
                filterKey: 'TargetGroupArn',
                filterValue: 'TargetGroupArn'
            },
            describeTags: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            sendIntegration: {
                enabled: true
            },
        },
        EMR: {
            describeCluster: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                filterKey: 'ClusterId',
                filterValue: 'Id'
            },
            listInstanceGroups: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                filterKey: 'ClusterId',
                filterValue: 'Id'
            },
            sendIntegration: serviceMap['EMR']
        },
        DLM: {
            getLifecyclePolicy: {
                reliesOnService: 'dlm',
                reliesOnCall: 'getLifecyclePolicies',
                filterKey: 'PolicyId',
                filterValue: 'PolicyId'
            }
        },
        ForecastService: {
            describeDataset: {
                reliesOnService: 'forecastservice',
                reliesOnCall: 'listDatasets',
                filterKey: 'DatasetArn',
                filterValue: 'DatasetArn'
            }
        },
        Glacier: {
            getVaultAccessPolicy: {
                reliesOnService: 'glacier',
                reliesOnCall: 'listVaults',
                filterKey: 'vaultName',
                filterValue: 'VaultName'
            },
            sendIntegration: serviceMap['Glacier']
        },
        IAM: {
            getGroup: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName'
            },
            listAttachedUserPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listAttachedGroupPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName'
            },
            listAttachedRolePolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName'
            },
            listUserPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listGroupPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName'
            },
            listRolePolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName'
            },
            listSSHPublicKeys: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listMFADevices: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listGroupsForUser: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 100
            },
            getInstanceProfile: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeInstances',
                override: true
            },
            sendIntegration: {
                enabled: true
            }
        },
        Kendra: {
            describeIndex:  {
                reliesOnService: 'kendra',
                reliesOnCall: 'listIndices',
                filterKey: 'Id',
                filterValue: 'Id'
            },
            sendIntegration: serviceMap['Kendra']
        },
        Kinesis: {
            describeStream: {
                reliesOnService: 'kinesis',
                reliesOnCall: 'listStreams',
                override: true
            }
        },
        Firehose: {
            describeDeliveryStream: {
                reliesOnService: 'firehose',
                reliesOnCall: 'listDeliveryStreams',
                override: true
            }
        },
        KMS: {
            describeKey: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                filterKey: 'KeyId',
                filterValue: 'KeyId'
            },
            getKeyRotationStatus: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                filterKey: 'KeyId',
                filterValue: 'KeyId'
            },
            getKeyPolicy: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                override: true
            },
            listResourceTags: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                filterKey: 'KeyId',
                filterValue: 'KeyId'
            },
            listGrants: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                override: true
            },
            sendIntegration: serviceMap['KMS']
        },
        Lambda: {
            getPolicy: {
                reliesOnService: 'lambda',
                reliesOnCall: 'listFunctions',
                filterKey: 'FunctionName',
                filterValue: 'FunctionName',
                rateLimit: 100, // it's not documented but experimentially 10/second works.
            },
            listTags: {
                reliesOnService: 'lambda',
                reliesOnCall: 'listFunctions',
                filterKey: 'Resource',
                filterValue: 'FunctionArn'
            },
            getFunctionUrlConfig :{
                reliesOnService: 'lambda',
                reliesOnCall: 'listFunctions',
                filterKey: 'FunctionName',
                filterValue: 'FunctionName',
            },
            sendIntegration: {
                enabled: true
            }
        },
        LookoutEquipment: {
            describeDataset: {
                reliesOnService: 'lookoutequipment',
                reliesOnCall: 'listDatasets',
                filterKey: 'DatasetName',
                filterValue: 'DatasetName'
            }
        },
        Location: {
            describeTracker: {
                reliesOnService: 'location',
                reliesOnCall: 'listTrackers',
                filterKey: 'TrackerName',
                filterValue: 'TrackerName'
            },
            describeGeofenceCollection: {
                reliesOnService: 'location',
                reliesOnCall: 'listGeofenceCollections',
                filterKey: 'CollectionName',
                filterValue: 'CollectionName'
            }
        },
        LookoutVision: {
            listModels: {
                reliesOnService: 'lookoutvision',
                reliesOnCall: 'listProjects',
                filterKey: 'ProjectName',
                filterValue: 'ProjectName'
            }
        },
        LexModelsV2: {
            listBotAliases: {
                reliesOnService: 'lexmodelsv2',
                reliesOnCall: 'listBots',
                filterKey: 'botId',
                filterValue: 'botId'
            }
        },
        QLDB: {
            describeLedger: {
                reliesOnService: 'qldb',
                reliesOnCall: 'listLedgers',
                filterKey: 'Name',
                filterValue: 'Name'
            },
            sendIntegration: serviceMap['QLDB']
        },
        ManagedBlockchain: {
            listMembers: {
                reliesOnService: 'managedblockchain',
                reliesOnCall: 'listNetworks',
                filterKey: 'NetworkId',
                filterValue: 'Id'
            }
        },
        MQ: {
            describeBroker: {
                reliesOnService: 'mq',
                reliesOnCall: 'listBrokers',
                filterKey: 'BrokerId',
                filterValue: 'BrokerId'
            }
        },
        LookoutMetrics: {
            describeAnomalyDetector: {
                reliesOnService: 'lookoutmetrics',
                reliesOnCall: 'listAnomalyDetectors',
                filterKey: 'AnomalyDetectorArn',
                filterValue: 'AnomalyDetectorArn'
            }
        },
        MWAA: {
            getEnvironment: {
                reliesOnService: 'mwaa',
                reliesOnCall: 'listEnvironments',
                override: true
            }
        },
        Proton: {
            getEnvironmentTemplate: {
                reliesOnService: 'proton',
                reliesOnCall: 'listEnvironmentTemplates',
                filterKey: 'name',
                filterValue: 'name'
            }
        },
        RDS: {
            describeDBParameters: {
                reliesOnService: 'rds',
                reliesOnCall: 'describeDBParameterGroups',
                override: true
            },
            describeDBSnapshotAttributes: {
                reliesOnService: 'rds',
                reliesOnCall: 'describeDBSnapshots',
                filterKey: 'DBSnapshotIdentifier',
                filterValue: 'DBSnapshotIdentifier'
            },
            sendIntegration: {
                enabled: true
            }
        },
        Route53: {
            listResourceRecordSets: {
                reliesOnService: 'route53',
                reliesOnCall: 'listHostedZones',
                filterKey: 'HostedZoneId',
                filterValue: 'Id'
            },
        },
        Route53Domains: {
            getDomainDetail: {
                reliesOnService: 'route53domains',
                reliesOnCall: 'listDomains',
                filterKey: 'DomainName',
                filterValue: 'DomainName'
            },
        },
        S3Control: {
            getPublicAccessBlock: {
                reliesOnService: 'sts',
                reliesOnCall: 'getCallerIdentity',
                override: true
            }
        },
        Redshift: {
            describeClusterParameters: {
                reliesOnService: 'redshift',
                reliesOnCall: 'describeClusterParameterGroups',
                filterKey: 'ParameterGroupName',
                filterValue: 'ParameterGroupName'
            },
            sendIntegration: serviceMap['Redshift']
        },
        SageMaker: {
            describeNotebookInstance: {
                reliesOnService: 'sagemaker',
                reliesOnCall: 'listNotebookInstances',
                filterKey: 'NotebookInstanceName',
                filterValue: 'NotebookInstanceName'
            }
        },
        SecretsManager: {
            describeSecret: {
                reliesOnService: 'secretsmanager',
                reliesOnCall: 'listSecrets',
                filterKey: 'SecretId',
                filterValue: 'ARN',
            },
            sendIntegration: serviceMap['Secrets Manager']
        },
        SES: {
            getIdentityDkimAttributes: {
                reliesOnService: 'ses',
                reliesOnCall: 'listIdentities',
                override: true,
                rateLimit: 1000
            }
        },
        SNS: {
            getTopicAttributes: {
                reliesOnService: 'sns',
                reliesOnCall: 'listTopics',
                filterKey: 'TopicArn',
                filterValue: 'TopicArn'
            }
        },
        SQS: {
            getQueueAttributes: {
                reliesOnService: 'sqs',
                reliesOnCall: 'listQueues',
                override: true
            }
        },
        Support: {
            describeTrustedAdvisorCheckResult: {
                reliesOnService: 'support',
                reliesOnCall: 'describeTrustedAdvisorChecks',
                filterKey: 'checkId',
                filterValue: 'id'
            },
        },
        WAFRegional: {
            listResourcesForWebACL: {
                reliesOnService: 'wafregional',
                reliesOnCall: 'listWebACLs',
                override: true
            }
        },
        WAFV2: {
            listResourcesForWebACL: {
                reliesOnService: 'wafv2',
                reliesOnCall: 'listWebACLs',
                override: true
            },
            getWebACLForCognitoUserPool: {
                reliesOnService: 'cognitoidentityserviceprovider',
                reliesOnCall: 'listUserPools',
                override: true
            }
        },
        GuardDuty: {
            getDetector: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
            getMasterAccount: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
            listFindings: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
            listPublishingDestinations: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
        },
    },
    {
        APIGateway: {
            getClientCertificate: {
                reliesOnService: 'apigateway',
                reliesOnCall: 'getRestApis',
                override: true
            },
            getIntegration: {
                reliesOnService: 'apigateway',
                reliesOnCall: 'getRestApis',
                override: true
            },
            sendIntegration: {
                enabled: true
            }
        },
        AppMesh: {
            describeVirtualGateway: {
                reliesOnService: 'appmesh',
                reliesOnCall: 'listMeshes',
                override: true
            }
        },
        EMR: {
            describeSecurityConfiguration: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                override: true
            }
        },
        IAM: {
            getUserPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                override: true
            },
            getGroupPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                override: true
            },
            getRolePolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                override: true
            },
            getPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listPolicies',
                filterKey: 'PolicyArn',
                filterValue: 'Arn'
            },
            getRole: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName'
            },
            getUser: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            }
        },
        EKS:{
            describeNodegroups: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            },
            sendIntegration: {
                enabled: true
            }
        },
        ECS: {
            describeContainerInstances:  {
                override:true
            },
            listTasks:  {
                reliesOnService: 'ecs',
                override:true,
                reliesOnCall: 'listClusters'
            },
            describeServices: {
                override:true
            }
        },
        LookoutVision: {
            describeModel: {
                reliesOnService: 'lookoutvision',
                reliesOnCall: 'listProjects',
                override: true
            }
        },
        GuardDuty: {
            getFindings: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
            describePublishingDestination: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
        },
        LexModelsV2:{
            describeBotAlias: {
                reliesOnService: 'lexmodelsv2',
                reliesOnCall: 'listBots',
                override: true,
            }
        },
        ManagedBlockchain: {
            getMember: {
                reliesOnService: 'managedblockchain',
                reliesOnCall: 'listNetworks',
                override: true
            }
        }
    },
    {
        IAM: {
            getPolicyVersion: {
                reliesOnService: 'iam',
                reliesOnCall: 'listPolicies',
                override: true
            }
        },
        ECS: {
            describeTasks:  {
                override:true
            },
            sendIntegration: {
                enabled: true
            }
        },
    }
];

module.exports = {
    globalServices: globalServices,
    serviceMap: serviceMap,
    calls: calls,
    postcalls: postcalls,
    integrationSendLast: integrationSendLast
};