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
    'EC2', 'IAM'
];

var calls = [
    {
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
        OpenSearchServerless: {
            listCollections : {
                paginate: 'NextToken',
                property: 'collectionSummaries'
            },
            listNetworkSecurityPolicies: {
                override: true,
            },
            listEncryptionSecurityPolicies:{
                override: true,
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
        Bedrock:{
            listCustomModels:{
                property: 'modelSummaries',
                paginate: 'NextToken',
            },
            listModelCustomizationJobs:{
                property: 'modelCustomizationJobSummaries"',
                paginate: 'NextToken',
            },
            getModelInvocationLoggingConfiguration: {
                property: 'loggingConfig',
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
                property: 'trailList',
                params: {
                    includeShadowTrails: false
                }
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
        CodePipeline: {
            listPipelines: {
                property: 'pipelines',
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
                paginate: 'NextToken'
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
    },
    {
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
        EMR: {
            listClusters: {
                property: 'Clusters',
                paginate: 'Marker',
                params: {
                    ClusterStates: [
                        'RUNNING'
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
                params: {
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
            },
        },
        HealthLake: {
            listFHIRDatastores: {
                property: 'DatastorePropertiesList',
                paginate: 'NextToken'
            },
        },
    },
    {
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
                override: true
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
        Kafka: {
            listClusters: {
                property: 'ClusterInfoList',
                paginate: 'NextToken'
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
                override: true
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
            },
        },
        STS: {
            getCallerIdentity: {
                property: 'Account'
            }
        },
        Support: {
            describeTrustedAdvisorChecks: {
                property: 'checks',
                params: {language: 'en'},
            },
        },
        SecurityHub: {
            describeHub: {
                property: '',
                paginate: 'NextToken'
            }
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
            describeWorkspaceDirectories: {
                property: 'Directories',
                paginate: 'NextToken'
            },
            describeIpGroups: {
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
    },
    {
        ELBv2: {
            describeLoadBalancers: {
                property: 'LoadBalancers',
                paginate: 'NextMarker',
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
        Imagebuilder: {
            listContainerRecipes: {
                property: 'containerRecipeSummaryList',
                paginate: 'nextToken'
            },
            listComponents: {
                property: 'componentVersionList',
                paginate: 'nextToken'
            },
            paginatelistImagePipelines: {
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
        CognitoIdentityServiceProvider: {
            listUserPools: {
                property: 'UserPools',
                paginate: 'NextToken',
                params: {
                    MaxResults: 60
                }
            },
        },
    }
];

var postcalls = [
    {
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
            }
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
            }
        },
        AppRunner: {
            describeService: {
                reliesOnService: 'apprunner',
                reliesOnCall: 'listServices',
                filterKey: 'ServiceArn',
                filterValue: 'ServiceArn'
            }
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
            }
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
            }
        },
        Bedrock:{
            getCustomModel: {
                reliesOnService: 'bedrock',
                reliesOnCall: 'listCustomModels',
                filterKey: 'modelIdentifier',
                filterValue: 'modelName',
            },
            getModelCustomizationJob: {
                reliesOnService: 'bedrock',
                reliesOnCall: 'listModelCustomizationJobs',
                filterKey: 'jobIdentifier',
                filterValue: 'jobArn',
            }
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
            getEc2MetricStatistics: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeInstances',
                override: true,
            },
            getredshiftMetricStatistics: {
                reliesOnService: 'redshift',
                reliesOnCall: 'describeClusters',
                override: true,
            },
            getRdsMetricStatistics: {
                reliesOnService: 'rds',
                reliesOnCall: 'describeDBInstances',
                override: true,
            },
            getRdsWriteIOPSMetricStatistics: {
                reliesOnService: 'rds',
                reliesOnCall: 'describeDBInstances',
                override: true,
            },
            getRdsReadIOPSMetricStatistics: {
                reliesOnService: 'rds',
                reliesOnCall: 'describeDBInstances',
                override: true,
            }
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
            }
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
            }
        },
        ElastiCache: {
            describeReplicationGroups: {
                reliesOnService: 'elasticache',
                reliesOnCall: 'describeCacheClusters',
                filterKey: 'ReplicationGroupId',
                filterValue: 'ReplicationGroupId'
            },
            describeCacheSubnetGroups: {
                reliesOnService: 'elasticache',
                reliesOnCall: 'describeCacheClusters',
                override: true
            },
        },
        ES: {
            describeElasticsearchDomain: {
                reliesOnService: 'es',
                reliesOnCall: 'listDomainNames',
                filterKey: 'DomainName',
                filterValue: 'DomainName'
            }
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
        }
    },
    {
        EC2: {
            describeSubnets: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeVpcs',
                override: true
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
            describeTargetGroupAttributes: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeTargetGroups',
                filterKey: 'TargetGroupArn',
                filterValue: 'TargetGroupArn'
            }
        },
        EMR: {
            describeCluster: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                filterKey: 'ClusterId',
                filterValue: 'Id'
            }
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
            }
        },
    },
    {
        EC2: {
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
        },
        ElasticBeanstalk: {
            describeConfigurationSettings: {
                reliesOnService: 'elasticbeanstalk',
                reliesOnCall: 'describeEnvironments',
                override: true
            }
        },
        ELB: {
            describeLoadBalancerAttributes: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
        },
        ELBv2: {
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
            listInstanceGroups: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                filterKey: 'ClusterId',
                filterValue: 'Id'
            }
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
            }
        },
    },
    {
        CloudFormation: {
            describeStackEvents: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName',
                rateLimit: 500 // ms to rate limit between stacks
            },
            describeStacks: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName',
                rateLimit: 500 // ms to rate limit between stacks
            },
            getTemplate: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName'
            },
        },
        WAFRegional: {
            listResourcesForWebACL: {
                reliesOnService: 'wafregional',
                reliesOnCall: 'listWebACLs',
                override: true,
                rateLimit: 600
            }
        },
        WAFV2: {
            listResourcesForWebACL: {
                reliesOnService: 'wafv2',
                reliesOnCall: 'listWebACLs',
                override: true,
                rateLimit: 600
            },
            getWebACLForCognitoUserPool: {
                reliesOnService: 'cognitoidentityserviceprovider',
                reliesOnCall: 'listUserPools',
                override: true
            },
            getWebACL: {
                reliesOnService: 'wafv2',
                reliesOnCall: 'listWebACLs',
                override: true
            }
        },
        ECS: {
            describeContainerInstances:  {
                override:true
            },
            listTasks:  {
                reliesOnService: 'ecs',
                reliesOnCall: 'listContainerInstances',
                override:true
            },
            describeServices: {
                override:true
            }
        },
    },
    {
        IAM: {
            getGroup: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName',
                rateLimit: 200
            },
            listAttachedUserPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 200
            },
            listAttachedGroupPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName',
                rateLimit: 200
            },
            listAttachedRolePolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName',
                rateLimit: 200
            },
            listUserPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 200
            },
            getInstanceProfile: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeInstances',
                override: true
            },
            listGroupPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName',
                rateLimit: 200
            },
            listSSHPublicKeys: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 200
            },
            listMFADevices: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 200
            },
            listGroupsForUser: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 500
            },
            sendIntegration: {
                enabled: true
            }
        },
        ECS: {
            describeTasks:  {
                override:true
            },
            sendIntegration: {
                enabled: true
            }
        }
    },
    {
        Kendra: {
            describeIndex:  {
                reliesOnService: 'kendra',
                reliesOnCall: 'listIndices',
                filterKey: 'Id',
                filterValue: 'Id'
            }
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
            }
        },
        Lambda: {
            getPolicy: {
                reliesOnService: 'lambda',
                reliesOnCall: 'listFunctions',
                filterKey: 'FunctionName',
                filterValue: 'FunctionName',
                rateLimit: 500, // it's not documented but experimentally 10/second works.
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
            }
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
            }
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
            }
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
                override: true,
                rateLimit: 500
            },
            getGroupPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                override: true,
                rateLimit: 500
            },
            getRolePolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                override: true,
                rateLimit: 500
            }
        },
        EKS: {
            describeNodegroups: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            },
            sendIntegration: {
                enabled: true
            }
        },
    },
    {
        IAM: {
            getPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listPolicies',
                filterKey: 'PolicyArn',
                filterValue: 'Arn',
                rateLimit: 500
            },
            getUser: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 500
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
                override: true,
                rateLimit: 500
            },
            getRole: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName',
                rateLimit: 500
            },
            listRolePolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName',
                rateLimit: 500
            }
        }
    },
    {
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
        CognitoIdentityServiceProvider: {
            describeUserPool: {
                reliesOnService: 'cognitoidentityserviceprovider',
                reliesOnCall: 'listUserPools',
                filterKey: 'UserPoolId',
                filterValue: 'Id'
            }
        },
        OpenSearchServerless: {
            getNetworkSecurityPolicy: {
                reliesOnService: 'opensearchserverless',
                reliesOnCall: 'listNetworkSecurityPolicies',
                override: true,
            },
            getEncryptionSecurityPolicy: {
                reliesOnService: 'opensearchserverless',
                reliesOnCall: 'listEncryptionSecurityPolicies',
                override: true,
            }
        }
    },
];

module.exports = {
    globalServicesMultipart: globalServices,
    callsMultipart: calls,
    postcallsMultipart: postcalls,
    integrationSendLast: integrationSendLast
};
