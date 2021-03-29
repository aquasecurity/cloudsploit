// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    acm: {
        listCertificate: 'CertificateArn',
        describeCertificate: 'Certificate.CertificateArn'
    },
    apigateway: {
        getRestApis: 'name'
    },
    athena:{
        getWorkGroup: 'WorkGroup.Name',
        listWorkGroups: 'Name'
    },
    cloudformation: {
        describeStacks: 'StackId'
    },
    cloudfront:{
        getDistribution: 'Distribution.ARN',
        listDistributions: 'ARN'
    },
    cloudtrail: {
        describeTrails: 'TrailARN',
        getEventSelectors: 'TrailARN',
    },
    cloudwatchlogs: {
        describeLogGroups: 'arn',
        describeConfigurationRecorders: 'roleARN'
    },
    comprehend: {
        listEntitiesDetectionJobs: 'JobName',
        listDominantLanguageDetectionJobs: 'JobName',
        listTopicsDetectionJobs: 'JobName',
        listDocumentClassificationJobs: 'JobName',
        listKeyPhrasesDetectionJobs: 'JobName',
        listSentimentDetectionJobs: 'JobName'
    },
    configservice: {
        describeConfigurationRecorderStatus: 'name',

    },
    dax: {
        describeClusters: 'ClusterArn'
    },
    dlm: {
        getLifecyclePolicies: 'PolicyId'
    },
    dms: {
        describeReplicationInstances: 'ReplicationInstanceIdentifier'
    },
    dynamodb: {
        describeTable: 'Table.TableArn'
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
        getEbsEncryptionByDefault: ''
    },
    ecr: {
        describeRepositories: '',
        getRepositoryPolicy: '',
    },
    ecs: {
        describeCluster: '',
        listClusters: '',
        listContainerInstances: ''
    },
    efs: {
        describeFileSystems: ''
    },
    eks: {
        describeCluster: 'cluster.arn',
    },
    elb: {
        describeLoadBalancerAttributes: '',
        describeLoadBalancerPolicies: '',
        describeLoadBalancers: '',
        describeTags: '',
    },
    elbv2: {
        describeLoadBalancers: 'LoadBalancerArn',
        describeTargetGroups: 'TargetGroupArn',
    },
    emr: {
        describeCluster: '',
        listClusters: ''
    },
    es:{
        describeElasticsearchDomain: 'ARN',
        listDomainNames: 'DomainName',
    },
    elasticbeanstalk: {
        describeConfigurationSettings: '',
        describeEnvironments: ''
    },
    elastictranscoder: {
        listPipelines: ''
    },
    firehose: {
        listDeliveryStreams: '',
        describeDeliveryStream: ''
    },
    glue: {
        getDataCatalogEncryptionSettings: '',
        getSecurityConfigurations: '',
    },
    iam: {
        generateCredentialReport: 'arn',
        getGroup: 'Group.GroupId',
        listGroups: 'GroupId',
        getUserPolicy: '',
        getRole: 'Role.Arn',
        listPolicies: 'Arn',
        listRoles: 'Arn',
        listServerCertificates: '',
        listUsers: 'Arn',
        listVirtualMFADevices: 'SerialNumber',
    },
    kms: {
        describeKey: 'KeyMetadata.Arn',
        listAliases: 'AliasArn',
        listKeys: 'KeyArn',
    },
    kinesis: {
        describeStream: 'StreamDescription.StreamARN',
        listStreams: '',
        listHandshakesForAccount: ''
    },
    lambda: {
        listFunctions: 'FunctionArn'
    },
    organizations: {
        describeOrganization: 'Arn',
        listAccounts: ''
    },
    rds: {
        describeDBClusters: 'DBClusterArn',
        describeDBEngineVersions: 'Engine',
        describeDBInstances: 'DBInstanceArn',
        describeDBParameterGroups: 'DBParameterGroupArn',
        describeDBSnapshots: 'DBSnapshotArn',
    },
    redshift: {
        describeClusterParameterGroups: '',
        describeClusterParameters: '',
        describeClusters: '',
        
    },
    s3: {
        listBuckets: 'name',
    },
    sns:{
        listTopics: 'describeKey',
        getTopicAttributes: 'Attributes.TopicArn'
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
        listAssociations: ''
    },
    sagemaker: {
        describeNotebookInstance: '',
        listNotebookInstances: ''
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
    transfer: {
        listServers: ''
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
        describeWorkspaces: ''
    },
    xray: {
        getEncryptionConfig: ''
    }
};