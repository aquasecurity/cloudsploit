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
        getRestApis: 'arn:aws:apigateway:{region}::/restapis/{id}',
        getStages: 'arn:aws:apigateway:{region}::/restapis/{resourceId}/stages/{stageName}',
        getClientCertificate: 'arn:aws:apigateway:{region}::/clientcertificates/{clientCertificateId}',
        getDomainNames: 'arn:aws:apigateway:{region}::/domainnames/{domainName}',
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
        listWorkGroups: 'arn:aws:athena:{region}:{cloudAccount}:workgroup/{Name}'
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
    bedrock: {
        listCustomModels: 'modelArn',
        getCustomModel: 'modelArn',
        listModelCustomizationJobs: 'jobArn',
        getModelCustomizationJob: 'jobArn',
        getModelInvocationLoggingConfiguration: ''

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
        describeMetricFilters: 'arn:aws:logs:{region}:{cloudAccount}:log-group:{logGroupName}'
    },
    codeartifact: {
        listDomains: 'arn',
    },
    codebuild: {
        listProjects: '',
        batchGetProjects: 'arn',
    },
    codepipeline: {
        listPipelines: 'arn:aws:codepipeline:{region}:{cloudAccount}:{name}',
        getPipeline: 'pipeline.roleArn',
    },
    codestar: {
        listProjects: 'projectArn',
        describeProject: 'arn'
    },
    cognitoidentityserviceprovider: {
        listUserPools: 'arn:aws:cognito-idp:{region}:{cloudAccount}:userpool/{Id}',
        describeUserPool: 'Arn',

    },
    comprehend: {
        listEntitiesDetectionJobs: 'JobId',
        listDominantLanguageDetectionJobs: 'JobId',
        listTopicsDetectionJobs: 'JobId',
        listDocumentClassificationJobs: 'JobId',
        listKeyPhrasesDetectionJobs: 'JobId',
        listSentimentDetectionJobs: 'JobId'
    },
    computeoptimizer: {
        getRecommendationSummaries: 'recommendationResourceType',
    },
    configservice: {
        describeConfigurationRecorderStatus: 'name',
        describeConfigRules: 'ConfigRuleArn',
        getComplianceDetailsByConfigRule: '',
        describeConfigurationRecorders: 'name',
        describeDeliveryChannels: 'name',
        getDiscoveredResourceCounts: 'resourceType'
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
        listDomains: 'arn:aws:profile:{region}:{cloudAccount}:domain/{DomainName}',
        getDomain: '',
    },
    dms: {
        describeReplicationInstances: 'ReplicationInstanceArn',
    },
    docdb: {
        describeDBClusters: 'DBClusterArn'
    },
    devopsguru: {
        listNotificationChannels: 'Id'
    },
    dax: {
        describeClusters: 'ClusterArn'
    },
    dlm: {
        getLifecyclePolicies: 'PolicyId',
        getLifecyclePolicy: 'PolicyArn',
    },
    dynamodb: {
        listTables: 'arn:aws:dynamodb:{region}:{cloudAccount}:table/{value}',
        listBackups: '',
        describeTable: 'Table.TableArn',
        describeContinuousBackups: '',
    },
    ec2: {
        describeAccountAttributes: 'AttributeName',
        describeAddresses: '',
        describeEgressOnlyInternetGateways: 'arn:aws:vpc:{region}:{cloudAccount}:egress-only-internet-gateway/{EgressOnlyInternetGatewayId}',
        describeFlowLogs: 'arn:aws:ec2:{region}:{cloudAccount}:flow-log/{FlowLogId}',
        describeImages: 'arn:aws:ec2:{region}:{cloudAccount}:image/${ImageId}',
        describeInstances: 'arn:aws:ec2:{region}:{cloudAccount}:instance/{InstanceId}',
        describeInternetGateways: 'arn:aws:vpc:{region}:{cloudAccount}:internet-gateway/{InternetGatewayId}',
        describeNatGateways: 'arn:aws:ec2:{region}:{cloudAccount}:natgateway/{NatGatewayId}',
        describeNetworkAcls: '`arn:aws:ec2:{region}:{cloudAccount}:network-acl/{NetworkAclId}',
        describeNetworkInterfaces: 'arn:aws:ec2:{region}:{cloudAccount}:network-interface/{NetworkInterfaceId}',
        describeRouteTables: 'RouteTableId',
        describeSecurityGroups: 'arn:aws:ec2:{region}:{OwnerId}:security-group/{GroupId}',
        describeSnapshotAttribute: '',
        describeSnapshots: 'arn:aws:ec2:{region}:{OwnerId}:snapshot/{SnapshotId}',
        describeSubnets: 'SubnetArn',
        describeTags: 'ResourceId',
        describeVolumes: 'arn:aws:ec2:{region}:{cloudAccount}:volume/{VolumeId}',
        describeVpcEndpointServices: 'arn:aws:ec2:{region}:{Owner}:vpc-endpoint-service/{ServiceId}',
        describeVpcEndpoints: 'arn:aws:ec2:{region}:{cloudAccount}:vpc-endpoint/{VpcEndpointId}',
        describeVpcPeeringConnections: 'arn:aws:ec2:{region}:{cloudAccount}:vpc-peering-connection/{VpcPeeringConnectionId}',
        describeVpcs: 'arn:aws:ec2:{region}:{cloudAccount}:vpc/{VpcId}',
        describeVpnConnections: 'arn:aws:ec2:{region}:{cloudAccount}:vpn-connection/{VpnConnectionId}',
        describeVpnGateways: 'arn:aws:vpc:{region}:{cloudAccount}:vpn-gateway/{VpnGatewayId}',
        getEbsDefaultKmsKeyId: '',
        getEbsEncryptionByDefault: '',
        describeLaunchTemplates: 'LaunchTemplateId',
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
        describeReplicationGroups: 'ReplicationGroupId',
        describeReservedCacheNodes: 'ReservationARN',
    },
    elb: {
        describeLoadBalancerAttributes: '',
        describeLoadBalancerPolicies: 'PolicyDescriptions.PolicyName',
        describeLoadBalancers: 'arn:aws:elasticloadbalancing:{region}:{cloudAccount}:loadbalancer/{LoadBalancerName}',
        describeTags: '',
    },
    elbv2: {
        describeLoadBalancers: 'LoadBalancerArn',
        describeLoadBalancerAttributes: '',
        describeTargetGroups: 'TargetGroupArn',
        describeTargetGroupAttributes: '',
        describeListeners: 'ListenerArn',
        describeTargetHealth: ''
    },
    emr: {
        describeCluster: 'Cluster.ClusterArn',
        listClusters: 'ClusterArn',
        listInstanceGroups: '',
        describeSecurityConfiguration: 'Name'
    },
    es:{
        describeElasticsearchDomain: 'DomainStatus.ARN',
        listDomainNames: 'arn:aws:es:{region}:{cloudAccount}:domain/{DomainName}',
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
        getSecurityConfigurations: 'arn:aws:glue:{region}:{cloudAccount}:/securityConfiguration/{Name}',
    },
    glacier: {
        listVaults: 'VaultARN'
    },
    databrew: {
        listJobs: 'ResourceArn',
    },
    guardduty: {
        listDetectors: 'arn:aws:guardduty:{region}:{cloudAccount}:detector/{value}',
        getDetector: 'detectorId',
        getMasterAccount: '',
        listFindings: '',
        getFindings: 'Findings.Id',
        listPublishingDestinations: 'arn:aws:guardduty:{region}:{cloudAccount}:detector/{}/publishingDestination/{DestinationId}',
        describePublishingDestination: 'DestinationId',
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
        listIndices: 'arn:aws:kendra:{region}:{cloudAccount}:index/{Name}',
        describeIndex: 'Id',

    },
    kinesis: {
        describeStream: 'StreamDescription.StreamARN',
        listStreams: 'arn:aws:kinesis:{region}:{cloudAccount}:stream/{value}',
    },
    kinesisvideo: {
        listStreams: 'StreamARN'
    },
    kms: {
        listKeys: 'KeyArn',
        describeKey: 'KeyMetadata.Arn',
        listAliases: 'AliasArn',
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
        listBots: 'arn:aws:lex:{region}:{cloudAccount}:bot/{botId}',
        listBotAliases: 'arn:aws:lex:{region}:{cloudAccount}:bot/{botAliasId}',
        describeBotAlias: '',
    },
    location: {
        listGeofenceCollections: 'arn:aws:geo:{region}:{cloudAccount}:geofence-collection/{CollectionName}',
        describeGeofenceCollection: 'CollectionArn',
        listTrackers: 'arn:aws:geo:{region}:{cloudAccount}:tracker/{TrackerName}',
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
        listEnvironments: 'arn:aws:airflow:{region}:{cloudAccount}:environment/{value}',
        getEnvironment: 'Environment.Arn',
    },
    neptune: {
        describeDBClusters: 'DBClusterArn',

    },
    organizations: {
        describeOrganization: 'MasterAccountArn',
        listHandshakesForAccount: 'Arn',
        listAccounts: 'Arn'
    },
    proton: {
        listEnvironmentTemplates: 'arn',
        getEnvironmentTemplate: 'environmentTemplate.arn',
    },
    qldb: {
        listLedgers: 'arn:aws:qldb:{region}:{cloudAccount}:ledger/{Name}',
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
        describeClusterParameterGroups: 'ParameterGroupName',
        describeClusterParameters: '',
        describeClusters: 'arn:aws:redshift:{region}:{cloudAccount}:cluster:{ClusterIdentifier}',
        describeLoggingStatus: '',
        describeReservedNodes: 'arn:aws:redshift:{region}:{cloudAccount}:reserved-node:{ReservedNodeId}',
        
    },
    route53: {
        listHostedZones: 'arn:aws:route53:::{Id}',
        listResourceRecordSets: '',
    },
    route53domains: {
        listDomains: 'DomainName',
        getDomainDetail: '',
    },
    s3: {
        listBuckets: 'arn:aws:s3:::{Name}',
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
        listQueues: 'arn:aws:sqs:{region}:{cloudAccount}:{queueName}'
    },
    ssm: {
        describeInstanceInformation: 'InstanceId',
        describeParameters: 'Name',
        listAssociations: 'AssociationId',
        getServiceSetting: 'ARN',
        describeSessions: 'arn:aws:ec2:{region}:{cloudAccount}:/instance/{Target}'
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
        describeTrustedAdvisorChecks: 'id',
    },
    timestreamwrite: {
        listDatabases: 'Arn',
    },
    translate: {
        listTextTranslationJobs: 'arn:aws:translate:{region}:{cloudAccount}:job/{JobName}'
    },
    transfer: {
        listServers: 'Arn'
    },
    waf: {
        listWebACLs: 'Arn'
    },
    wisdom: {
        listAssistants: 'assistantArn'
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
        describeIpGroups: 'groupId',
        describeWorkspaceDirectories: 'DirectoryId',
        describeWorkspaces: 'arn:aws:workspaces:{region}:{cloudAccount}:workspace/{WorkspaceId}',
        describeWorkspacesConnectionStatus: ''
    },
    xray: {
        getEncryptionConfig: 'KeyId'
    }
};