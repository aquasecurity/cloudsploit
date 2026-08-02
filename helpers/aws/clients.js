const { AccessAnalyzer } = require ('@aws-sdk/client-accessanalyzer');
const { ACM } = require('@aws-sdk/client-acm');
const { APIGateway } = require('@aws-sdk/client-api-gateway');
const { ApiGatewayV2 } = require('@aws-sdk/client-apigatewayv2');
const { AppRunner } = require('@aws-sdk/client-apprunner');
const { Athena } = require('@aws-sdk/client-athena');
const { AuditManager } = require('@aws-sdk/client-auditmanager');
const { AutoScaling } = require('@aws-sdk/client-auto-scaling');
const { Backup } = require('@aws-sdk/client-backup');
const { AppConfig } = require('@aws-sdk/client-appconfig');
const { CloudFormation } = require('@aws-sdk/client-cloudformation');
const { CognitoIdentityProvider } = require('@aws-sdk/client-cognito-identity-provider');
const { Comprehend } = require('@aws-sdk/client-comprehend');
const { ComputeOptimizer } = require('@aws-sdk/client-compute-optimizer');
const { ConfigService } = require('@aws-sdk/client-config-service');
const { STS } = require('@aws-sdk/client-sts');
const { Bedrock } = require('@aws-sdk/client-bedrock');
const { S3 } = require ('@aws-sdk/client-s3');
const { DynamoDB } = require ('@aws-sdk/client-dynamodb');
const { EC2 } = require('@aws-sdk/client-ec2');
const { Lambda } = require('@aws-sdk/client-lambda');
const { RDS } = require('@aws-sdk/client-rds');
const { SNS } = require('@aws-sdk/client-sns');
const { SQS } = require('@aws-sdk/client-sqs');
const { IAM } = require('@aws-sdk/client-iam');
const { CloudWatch } = require('@aws-sdk/client-cloudwatch');
const { CloudFront } = require('@aws-sdk/client-cloudfront');
const { CodeBuild } = require('@aws-sdk/client-codebuild');
const { CustomerProfiles } = require('@aws-sdk/client-customer-profiles');
const { Connect } = require('@aws-sdk/client-connect');
const { DatabaseMigrationService } = require('@aws-sdk/client-database-migration-service');
const { DevOpsGuru } = require('@aws-sdk/client-devops-guru');
const { Route53 } = require('@aws-sdk/client-route-53');
const { Route53Domains } = require('@aws-sdk/client-route-53-domains');
const { WAFRegional } = require('@aws-sdk/client-waf-regional');
const { WAF } = require('@aws-sdk/client-waf');
const { CloudTrail } = require('@aws-sdk/client-cloudtrail');
const { TimestreamWrite } = require('@aws-sdk/client-timestream-write');
const { Redshift } = require('@aws-sdk/client-redshift');
const { DocDB } = require('@aws-sdk/client-docdb');
const { Neptune } = require('@aws-sdk/client-neptune');
const { ElastiCache } = require('@aws-sdk/client-elasticache');
const { MemoryDB } = require('@aws-sdk/client-memorydb');
const { Kendra } = require('@aws-sdk/client-kendra');
const { QLDB } = require('@aws-sdk/client-qldb');
const { EFS } = require('@aws-sdk/client-efs');
const { Glacier } = require('@aws-sdk/client-glacier');
const { KMS } = require('@aws-sdk/client-kms');
const { SecretsManager } = require('@aws-sdk/client-secrets-manager');
const { CloudWatchLogs } = require('@aws-sdk/client-cloudwatch-logs');
const { EventBridge } = require('@aws-sdk/client-eventbridge');
const { AppMesh } = require('@aws-sdk/client-app-mesh');
const { EMR } = require('@aws-sdk/client-emr');
const { Codeartifact } = require('@aws-sdk/client-codeartifact');
const { CodePipeline } = require('@aws-sdk/client-codepipeline');
const { SSM } = require('@aws-sdk/client-ssm');
const { SageMaker } = require('@aws-sdk/client-sagemaker');
const { Proton } = require('@aws-sdk/client-proton');
const { Organizations } = require('@aws-sdk/client-organizations');
const { MWAA } = require('@aws-sdk/client-mwaa');
const { ManagedBlockchain } = require('@aws-sdk/client-managedblockchain');
const { LookoutVision } = require('@aws-sdk/client-lookoutvision');
const { LookoutEquipment } = require('@aws-sdk/client-lookoutequipment');
const { LookoutMetrics } = require('@aws-sdk/client-lookoutmetrics');
const { Location } = require('@aws-sdk/client-location');
const { LexModelsV2 } = require('@aws-sdk/client-lex-models-v2');
const { KinesisVideo } = require('@aws-sdk/client-kinesis-video');
const { DAX } = require('@aws-sdk/client-dax');
const { ECR } = require('@aws-sdk/client-ecr');
const { ECS } = require('@aws-sdk/client-ecs');
const { EKS } = require('@aws-sdk/client-eks');
const { ElasticBeanstalk } = require('@aws-sdk/client-elastic-beanstalk');
const { ElasticTranscoder } = require('@aws-sdk/client-elastic-transcoder');
const { ElasticLoadBalancing } = require('@aws-sdk/client-elastic-load-balancing');
const { ElasticLoadBalancingV2 } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { Finspace } = require('@aws-sdk/client-finspace');
const { Firehose } = require('@aws-sdk/client-firehose');
const { Forecast } = require ('@aws-sdk/client-forecast');
const { FraudDetector } = require('@aws-sdk/client-frauddetector');
const { FSx } = require('@aws-sdk/client-fsx');
const { Glue } = require('@aws-sdk/client-glue');
const { DataBrew } = require('@aws-sdk/client-databrew');
const { GuardDuty } = require('@aws-sdk/client-guardduty');
const { HealthLake } = require('@aws-sdk/client-healthlake');
const { Imagebuilder } = require('@aws-sdk/client-imagebuilder');
const { IoTSiteWise } = require('@aws-sdk/client-iotsitewise');
const { Kinesis } = require('@aws-sdk/client-kinesis');
const { Mq } = require('@aws-sdk/client-mq');
const { Kafka } = require ('@aws-sdk/client-kafka');
const { OpenSearch } = require('@aws-sdk/client-opensearch');
const { OpenSearchServerless } = require('@aws-sdk/client-opensearchserverless');
const { SecurityHub } = require('@aws-sdk/client-securityhub');
const { SES } = require ('@aws-sdk/client-ses');
const { Shield } = require('@aws-sdk/client-shield');
const { Transfer } = require('@aws-sdk/client-transfer');
const { Translate } = require('@aws-sdk/client-translate');
const { WAFV2 } = require('@aws-sdk/client-wafv2');
const { WorkSpaces } = require('@aws-sdk/client-workspaces');
const { XRay } = require('@aws-sdk/client-xray');
const { Appflow } = require('@aws-sdk/client-appflow');
const { DLM } = require('@aws-sdk/client-dlm');
const { ResourceGroupsTaggingAPI } = require('@aws-sdk/client-resource-groups-tagging-api');
const { VoiceID } = require('@aws-sdk/client-voice-id');
const {Wisdom} = require('@aws-sdk/client-wisdom');

module.exports = {
    s3: S3,
    dynamodb: DynamoDB,
    accessanalyzer: AccessAnalyzer,
    ec2: EC2,
    lambda: Lambda,
    rds: RDS,
    sns: SNS,
    sqs: SQS,
    iam: IAM,
    cloudwatch: CloudWatch,
    cloudfront: CloudFront,
    route53: Route53,
    route53domains: Route53Domains,
    wafregional: WAFRegional,
    waf: WAF,
    cloudtrail: CloudTrail,
    athena: Athena,
    timestreamwrite: TimestreamWrite,
    redshift: Redshift,
    docdb: DocDB,
    neptune: Neptune,
    elasticache: ElastiCache,
    memorydb: MemoryDB,
    kendra: Kendra,
    qldb: QLDB,
    backup: Backup,
    efs: EFS,
    glacier: Glacier,
    kms: KMS,
    secretsmanager: SecretsManager,
    cloudwatchlogs: CloudWatchLogs,
    eventbridge: EventBridge,
    appmesh: AppMesh,
    apprunner: AppRunner,
    autoscaling: AutoScaling,
    emr: EMR,
    codeartifact: Codeartifact,
    codepipeline: CodePipeline,
    connect: Connect,
    dms: DatabaseMigrationService,
    cloudformation: CloudFormation,
    codebuild: CodeBuild,
    ssm: SSM,
    sagemaker: SageMaker,
    proton: Proton,
    organizations: Organizations,
    mwaa: MWAA,
    managedblockchain: ManagedBlockchain,
    lookoutvision: LookoutVision,
    lookoutequipment: LookoutEquipment,
    lookoutmetrics: LookoutMetrics,
    location: Location,
    lexmodelsv2: LexModelsV2,
    kinesisvideo: KinesisVideo,
    acm: ACM,
    apigateway: APIGateway,
    apigatewayv2: ApiGatewayV2,
    auditmanager: AuditManager,
    bedrock: Bedrock,
    cognitoidentityserviceprovider: CognitoIdentityProvider,
    comprehend: Comprehend,
    sts: STS,
    computeoptimizer: ComputeOptimizer,
    configservice: ConfigService,
    customerprofiles: CustomerProfiles,
    devopsguru: DevOpsGuru,
    dax: DAX,
    ecr: ECR,
    ecs: ECS,
    eks: EKS,
    elasticbeanstalk: ElasticBeanstalk,
    elastictranscoder: ElasticTranscoder,
    elb: ElasticLoadBalancing,
    elbv2: ElasticLoadBalancingV2,
    finspace: Finspace,
    firehose: Firehose,
    frauddetector: FraudDetector,
    fsx: FSx,
    glue: Glue,
    databrew: DataBrew,
    guardduty: GuardDuty,
    healthlake: HealthLake,
    imagebuilder: Imagebuilder,
    iotsitewise: IoTSiteWise,
    kinesis: Kinesis,
    mq: Mq,
    kafka: Kafka,
    opensearch: OpenSearch,
    opensearchserverless: OpenSearchServerless,
    securityhub: SecurityHub,
    ses: SES,
    shield: Shield,
    transfer: Transfer,
    translate: Translate,
    wafv2: WAFV2,
    workspaces: WorkSpaces,
    xray: XRay,
    appconfig: AppConfig,
    appflow: Appflow,
    dlm: DLM,
    forecastservice: Forecast,
    resourcegroupstaggingapi: ResourceGroupsTaggingAPI,
    voiceid: VoiceID,
    wisdom: Wisdom
};
