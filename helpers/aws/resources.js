// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    acm: {
        listCertificates: 'CertificateArn',
        describeCertificate: 'Certificate.CertificateArn'
    },
    accessanalyzer: {
        listAnalyzers: 'arn',
        listFindings: ''
    },
    apigateway: {
        getRestApis: 'name',
        getStages: '',
        getClientCertificate: ''
    },
    appflow: {
        listFlows: 'flowArn',
        describeFlow: 'flowArn'
    },
    appmesh: {
        listMeshes: 'arn',
        describeMesh: 'mesh.metadata.arn',
        listVirtualGateways: 'arn',
        describeVirtualGateway: 'virtualGateway.metadata.arn'
    },
    apprunner: {
        listServices: 'ServiceArn',
        describeService: 'Service.ServiceArn'
    },
    athena:{
        getWorkGroup: 'WorkGroup.Name',
        listWorkGroups: 'Name'
    },
    auditmanager: {
        getSettings: '',
    },
    autoscaling: {
        describeAutoScalingGroups: 'AutoScalingGroupARN',
        describeLaunchConfigurations: 'LaunchConfigurationARN',
        describeNotificationConfigurations: 'TopicARN',

    },
    backup: {
        listBackupVaults: 'BackupVaultArn',
        getBackupVaultAccessPolicy: 'BackupVaultArn',
        getBackupVaultNotifications: 'BackupVaultArn',
        describeRegionSettings: '',
        getBackupPlan: 'BackupPlanArn'
    },
    cloudformation: {
        describeStacks: 'StackId',
        listStacks: 'StackId',
        describeStackEvents: 'StackId'
    },
    cloudfront:{
        getDistribution: 'Distribution.ARN',
        listDistributions: 'ARN'
    },
    cloudtrail: {
        describeTrails: 'TrailARN',
        getEventSelectors: 'TrailARN',
        getTrailStatus: '',
        listTags: ''
    },
    cloudwatch: {
        describeAlarms: 'AlarmArn'
    },
    cloudwatchlogs: {
        describeLogGroups: 'arn',
        describeConfigurationRecorders: 'roleARN',
        describeMetricFilters: ''
    },
    codeartifact: {
        listDomains: 'arn',
    },
    codebuild: {
        listProjects: '',
        batchGetProjects: '',
    },
    codepipeline: {
        listPipelines: '',
        getPipeline: 'pipeline.roleArn',
    },
    codestar: {
        listProjects: 'projectArn',
        describeProject: 'arn'
    },
    cognitoidentityserviceprovider: {
        listUserPools: '',
        describeUserPool: 'Arn',

    },
    comprehend: {
        listEntitiesDetectionJobs: 'JobName',
        listDominantLanguageDetectionJobs: 'JobName',
        listTopicsDetectionJobs: 'JobName',
        listDocumentClassificationJobs: 'JobName',
        listKeyPhrasesDetectionJobs: 'JobName',
        listSentimentDetectionJobs: 'JobName'
    },
    computeoptimizer: {
        getRecommendationSummaries: '',
    },
    configservice: {
        describeConfigurationRecorderStatus: 'name',
        describeConfigRules: 'ConfigRuleArn',
        getComplianceDetailsByConfigRule: '',
        describeConfigurationRecorders: '',
        describeDeliveryChannels: '',
        getDiscoveredResourceCounts: ''
    },
    connect: {
        listInstances: 'Arn',
        instanceAttachmentStorageConfigs: '',
        listInstanceCallRecordingStorageConfigs: '',
        listInstanceMediaStreamStorageConfigs: '',
        listInstanceExportedReportStorageConfigs: '',
        listInstanceChatTranscriptStorageConfigs: '',
    },
    customerprofiles: {
        listDomains: '',
        getDomain: '',
    },
    dms: {
        describeReplicationInstances: 'ReplicationInstanceArn',
    },
    docdb: {
        describeDBClusters: 'DBClusterArn'
    },
    devopsguru: {
        listNotificationChannels: ''
    },
    dax: {
        describeClusters: 'ClusterArn'
    },
    dlm: {
        getLifecyclePolicies: 'PolicyId',
        getLifecyclePolicy: '',
    },
    dynamodb: {
        listTables: '',
        listBackups: '',
        describeTable: 'Table.TableArn',
        describeContinuousBackups: '',
    },
    ec2: {
        describeAccountAttributes: 'AttributeName',
        describeAddresses: '',
        describeEgressOnlyInternetGateways: '',
        describeFlowLogs: '',
        describeImages: '',
        describeInstances: 'InstanceId',
        describeInternetGateways: 'InternetGatewayId',
        describeNatGateways: '',
        describeNetworkAcls: 'NetworkAclId',
        describeNetworkInterfaces: 'NetworkInterfaceId',
        describeRouteTables: 'RouteTableId',
        describeSecurityGroups: 'GroupId',
        describeSnapshotAttribute: '',
        describeSnapshots: '',
        describeSubnets: 'SubnetArn',
        describeTags: 'ResourceId',
        describeVolumes: 'VolumeId',
        describeVpcEndpointServices: 'ServiceId',
        describeVpcEndpoints: '',
        describeVpcPeeringConnections: '',
        describeVpcs: 'VpcId',
        describeVpnConnections: '',
        describeVpnGateways: '',
        getEbsDefaultKmsKeyId: '',
        getEbsEncryptionByDefault: '',
        describeLaunchTemplates: '',
        describeLaunchTemplateVersions: ''
    },
    ecr: {
        describeRepositories: 'repositoryArn',
        getRepositoryPolicy: '',
    },
    ecs: {
        describeCluster: 'clusterArn',
        listClusters: '',
        listContainerInstances: ''
    },
    efs: {
        describeFileSystems: 'FileSystemArn'
    },
    eks: {
        listClusters: '',
        describeCluster: 'cluster.arn',
    },
    elasticache: {
        describeCacheClusters: 'ARN',
        describeReplicationGroups: '',
        describeReservedCacheNodes: 'ReservationARN',
    },
    elb: {
        describeLoadBalancerAttributes: '',
        describeLoadBalancerPolicies: '',
        describeLoadBalancers: '',
        describeTags: '',
    },
    elbv2: {
        describeLoadBalancers: 'LoadBalancerArn',
        describeLoadBalancerAttributes: '',
        describeTargetGroups: 'TargetGroupArn',
        describeTargetGroupAttributes: '',
        describeListeners: '',
        describeTargetHealth: ''
    },
    emr: {
        describeCluster: 'Cluster.ClusterArn',
        listClusters: 'ClusterArn',
        listInstanceGroups: '',
        describeSecurityConfiguration: ''
    },
    es:{
        describeElasticsearchDomain: 'DomainStatus.ARN',
        listDomainNames: 'DomainName',
    },
    elasticbeanstalk: {
        describeConfigurationSettings: 'PlatformArn',
        describeEnvironments: 'EnvironmentArn'
    },
    elastictranscoder: {
        listPipelines: 'Arn',
        listJobsByPipeline: 'Arn'
    },
    eventbridge: {
        listEventBuses: 'Arn',
        listRules: 'Arn'
    },
    finspace: {
        listEnvironments: 'environmentArn'
    },
    firehose: {
        listDeliveryStreams: '',
        describeDeliveryStream: 'DeliveryStreamDescription.DeliveryStreamARN'
    },
    forecastservice: {
        listForecastExportJobs: 'ForecastExportJobArn',
        listDatasets: 'DatasetArn',
        describeDataset: 'DatasetArn'
    },
    frauddetector: {
        getDetectors: 'arn',
        getKMSEncryptionKey: 'kmsEncryptionKeyArn',
    },
    fsx: {
        describeFileSystems: 'ResourceARN'
    },
    glue: {
        getDataCatalogEncryptionSettings: '',
        getSecurityConfigurations: '',
    },
    glacier: {
        listVaults: ''
    },
    databrew: {
        listJobs: 'ResourceArn',
    },
    guardduty: {
        listDetectors: '',
        getDetector: '',
        getMasterAccount: '',
        listFindings: '',
        getFindings: '',
        listPublishingDestinations: '',
        describePublishingDestination: '',
    },
    healthlake: {
        listFHIRDatastores: 'DatastoreArn'
    },
    iam: {
        generateCredentialReport: 'arn',
        getGroup: 'Group.Arn',
        listGroups: 'Arn',
        getUserPolicy: '',
        getRole: 'Role.Arn',
        listPolicies: 'Arn',
        listRoles: 'Arn',
        listServerCertificates: 'Arn',
        listUsers: 'Arn',
        listVirtualMFADevices: 'SerialNumber',
        getAccountPasswordPolicy: '',
        getAccountSummary: '',
        listAttachedUserPolicies: 'PolicyArn',
        listAttachedGroupPolicies: '',
        listAttachedRolePolicies: '',
        listUserPolicies: '',
        listGroupPolicies: '',
        listRolePolicies: '',
        listSSHPublicKeys: '',
        listMFADevices: '',
        listGroupsForUser: '',
        getGroupPolicy: '',
        getRolePolicy: '',
        getPolicy: 'Policy.Arn', 
        getUser: 'Arn'
    },
    imagebuilder: {
        listContainerRecipes: 'arn',
        getContainerRecipe: 'containerRecipe.ARN',
        listImagePipelines: 'arn',
        listImageRecipes: 'arn',
        getImageRecipe: 'imageRecipe.ARN',
        listComponents: 'arn',
        getComponent: 'component.arn',
        listInfrastructureConfigurations: 'arn',
        getInfrastructureConfiguration: 'infrastructureConfiguration.arn'

    },
    iotsitewise: {
        describeDefaultEncryptionConfiguration: 'kmsKeyArn'
    },
    kendra: {
        listIndices: '',
        describeIndex: '',

    },
    kinesis: {
        describeStream: 'StreamDescription.StreamARN',
        listStreams: '',
    },
    kinesisvideo: {
        listStreams: 'StreamARN'
    },
    kms: {
        listKeys: 'KeyArn',
        describeKey: 'KeyMetadata.Arn',
        listAliases: '',
        listResourceTags: '',
        listGrants: '',
        getKeyPolicy: '',
        getKeyRotationStatus: '',
    },
    lambda: {
        listFunctions: 'FunctionArn',
        getPolicy: '',
        listTags: '',
    },
    lexmodelsv2: {
        listBots: '',
        listBotAliases: '',
        describeBotAlias: '',
    },
    location: {
        listGeofenceCollections: '',
        describeGeofenceCollection: 'CollectionArn',
        listTrackers: '',
        describeTracker: 'TrackerArn'
    },
    lookoutmetrics: {
        listAnomalyDetectors: 'AnomalyDetectorArn',
        describeAnomalyDetector: 'AnomalyDetectorArn'
    },
    lookoutequipment: {
        listDatasets: 'DatasetArn',
        describeDataset: 'DatasetArn'
    },
    lookoutvision: {
        listProjects: 'ProjectArn',
        listModels: 'ModelArn',
        describeModel: 'ModelDescription.ModelArn'
    },
    managedblockchain: {
        listMembers: 'Arn',
        listNetworks: 'Arn',
        getMember: 'Arn'
    },
    memorydb: {
        describeClusters: 'ARN',
    },
    mq: {
        listBrokers: 'BrokerArn',
        describeBroker: 'BrokerArn'
    },
    kafka: {
        listClusters: 'ClusterArn',
    },
    mwaa: {
        listEnvironments: '',
        getEnvironment: 'Environment.Arn',
    },
    neptune: {
        describeDBClusters: 'DBClusterArn',

    },
    organizations: {
        describeOrganization: 'Arn',
        listHandshakesForAccount: 'Arn',
        listAccounts: ''
    },
    proton: {
        listEnvironmentTemplates: 'arn',
        getEnvironmentTemplate: 'environmentTemplate.arn',
    },
    qldb: {
        listLedgers: '',
        describeLedger: 'Arn',
    },
    rds: {
        describeDBClusters: 'DBClusterArn',
        describeDBEngineVersions: 'Engine',
        describeDBInstances: 'DBInstanceArn',
        describeDBParameters: '',
        describeDBParameterGroups: 'DBParameterGroupArn',
        describeDBSnapshots: 'DBSnapshotArn',
    },
    redshift: {
        describeClusterParameterGroups: '',
        describeClusterParameters: '',
        describeClusters: '',
        describeLoggingStatus: '',
        describeReservedNodes: '',
        
    },
    route53: {
        listHostedZones: '',
        listResourceRecordSets: '',
    },
    route53domains: {
        listDomains: '',
        getDomainDetail: '',
    },
    s3: {
        listBuckets: 'name',
        listObjects: '',
        getBucketAcl: '',
        getBucketLocation: '',
        getBucketPolicy: '',
        getBucketEncryption: '',
        getBucketWebsite: '',
        getBucketLifecycleConfiguration: '',
        getBucketLogging: '',
        getPublicAccessBlock: '',
        getBucketAccelerateConfiguration: '',
        getBucketVersioning: ''
    },
    secretsmanager: {
        listSecrets: 'ARN',
        describeSecret: 'ARN',
    },
    sns:{
        listTopics: 'TopicArn',
        getTopicAttributes: 'Attributes.TopicArn',
        listSubscriptions: 'SubscriptionArn',
    },
    ses: {
        describeActiveReceiptRuleSet: 'Name',
        getIdentityDkimAttributes: '',
        listIdentities: ''
    },
    sqs: {
        getQueueAttributes: 'Attributes.QueueArn',
        listQueues: ''
    },
    ssm: {
        describeInstanceInformation: 'InstanceId',
        describeParameters: 'Name',
        listAssociations: '',
        getServiceSetting: 'ARN',
        describeSessions: ''
    },
    sagemaker: {
        describeNotebookInstance: 'NotebookInstanceArn',
        listNotebookInstances: 'NotebookInstanceArn'
    },
    shield: {
        describeEmergencyContactSettings: '',
        describeSubscription: '',
        listProtections: ''
    },
    support: {
        describeTrustedAdvisorCheckResult: '',
        describeTrustedAdvisorChecks: '',
    },
    timestreamwrite: {
        listDatabases: 'Arn',
    },
    translate: {
        listTextTranslationJobs: ''
    },
    transfer: {
        listServers: 'Arn'
    },
    waf: {
        listWebACLs: ''
    },
    wisdom: {
        listAssistants: ''
    },
    wafRegional: {
        listResourcesForWebACL: '',
        listWebACLs: 'WebACLId'
    },
    wafv2: {
        listResourcesForWebACL: '',
        listWebACLs: 'ARN'
    },
    workspaces: {
        describeIpGroups: '',
        describeWorkspaceDirectories: '',
        describeWorkspaces: '',
        describeWorkspacesConnectionStatus: ''
    },
    xray: {
        getEncryptionConfig: 'KeyId'
    }
};