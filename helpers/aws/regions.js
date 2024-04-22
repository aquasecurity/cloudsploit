// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'us-east-1',        // Northern Virginia
    'us-east-2',        // Ohio
    'us-west-1',        // Northern California
    'us-west-2',        // Oregon
    'af-south-1',        // Africa (Cape Town)
    'ap-east-1',        // Asia Pacific (Hong Kong)
    'ap-south-1',       // Asia Pacific (Mumbai)
    'ap-northeast-3',   // Asia Pacific (Osaka)
    'ca-central-1',     // Canada (Montreal)
    'eu-central-1',     // EU (Frankfurt)
    'eu-west-1',        // EU (Ireland)
    'eu-west-2',        // London
    'eu-west-3',        // Paris
    'eu-north-1',       // Stockholm
    'eu-south-1',       // EU (Milan)
    'ap-northeast-1',   // Asia Pacific (Tokyo)
    'ap-northeast-2',   // Asia Pacific (Seoul)
    'ap-southeast-1',   // Asia Pacific (Singapore)
    'ap-southeast-2',   // Asia Pacific (Sydney)
    'sa-east-1',        // South America (São Paulo)
    'me-south-1',       // Middle East (Bahrain),
    'me-central-1',     // Middle East (UAE),
    'ap-southeast-3',   // Asia Pacific (Jakarta)
];

var newRegionsUpdate =[
    'ap-south-2',       // Asia Pacific (Hyderabad)
    'ap-southeast-4',   // Asia Pacific (Melbourne)
    'eu-south-2',      // Europe (Spain)
    'eu-central-2',    // Europe (Zurich)
    'il-central-1',   //Israel (Tel Aviv)
    'ca-west-1',      //Canada West (Calgary)
];

module.exports = {
    default: ['us-east-1'],
    all: [...regions, ...newRegionsUpdate],
    optin: ['ap-east-1', 'me-south-1', 'ap-southeast-3'],   // Regions that AWS disables by default
    accessanalyzer: [...regions, ...newRegionsUpdate],
    acm: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    apigateway: [...regions, ...newRegionsUpdate],
    athena:[...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    bedrock: ['us-east-1', 'us-west-2', 'ap-southeast-1', 'ap-northeast-1', 'eu-central-1'],
    cloudfront: ['us-east-1'], // CloudFront uses the default global region
    autoscaling: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    iam: ['us-east-1'],
    route53: ['us-east-1'],
    route53domains: ['us-east-1'],
    s3: ['us-east-1'],
    s3control: ['us-east-1'],
    cognitoidentityserviceprovider: ['us-east-1','us-east-2','us-west-1','us-west-2','af-south-1','ap-southeast-3',
        'ap-south-1','ap-northeast-3','ap-northeast-2','ap-southeast-1','ap-southeast-2',
        'ap-northeast-1','ca-central-1','eu-central-1','eu-west-1','eu-west-2','eu-south-1',
        'eu-west-3','eu-north-1','il-central-1','me-south-1','sa-east-1'],
    cloudformation: [...regions, ...newRegionsUpdate],
    cloudtrail: [...regions, ...newRegionsUpdate],
    cloudwatchlogs: [...regions,...newRegionsUpdate],
    comprehend: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1',
        'ap-southeast-2', 'ap-northeast-2', 'ap-south-1', 'ca-central-1'],
    configservice: [...regions, ...newRegionsUpdate],
    dax: ['us-east-1'], // available Globally
    devopsguru: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2','eu-west-1', 'eu-west-2', 'eu-west-3','ap-northeast-1', 'eu-central-1',
        'ap-southeast-1', 'ap-southeast-2', 'eu-north-1', 'ap-south-1', 'ap-northeast-2', 'ca-central-1','eu-central-1',
        'sa-east-1'],
    dynamodb: [...regions, ...newRegionsUpdate],
    docdb: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'eu-south-1', 'ap-east-1', 'ap-south-2'],
    dlm: [...regions, ...newRegionsUpdate],
    dms: [...regions, ...newRegionsUpdate],
    ec2: [...regions, ...newRegionsUpdate],
    ecr: [...regions, ...newRegionsUpdate],
    eks: [...regions, ...newRegionsUpdate],
    elasticbeanstalk: [...regions, 'il-central-1'],
    elastictranscoder: ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-south-1'],
    elb: [...regions, ...newRegionsUpdate],
    elbv2: [...regions, ...newRegionsUpdate],
    eventbridge: [...regions, ...newRegionsUpdate],
    emr: [...regions, ...newRegionsUpdate],
    es: [...regions, ...newRegionsUpdate],
    glue: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    kinesis: [...regions, ...newRegionsUpdate],
    kinesisvideo:  ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-northeast-1','ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'ap-east-1','sa-east-1', 'af-south-1'],
    firehose: [...regions, ...newRegionsUpdate],
    kms: [...regions, ...newRegionsUpdate],
    vpc: [...regions, ...newRegionsUpdate],
    flowlogs: [...regions, ...newRegionsUpdate],
    rds: [...regions, ...newRegionsUpdate],
    redshift: [...regions, ...newRegionsUpdate],
    cloudwatch: [...regions, ...newRegionsUpdate],
    ecs: [...regions, ...newRegionsUpdate],
    resourcegroupstaggingapi: [...regions, ...newRegionsUpdate],
    sagemaker: [...regions, ...newRegionsUpdate],
    secretsmanager: [...regions, ...newRegionsUpdate],
    ses: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-3', 'ap-south-1',
        'sa-east-1', 'me-south-1', 'af-south-1', 'ap-southeast-3', 'il-central-1'],
    sns: [...regions, ...newRegionsUpdate],
    securityhub: [...regions, ...newRegionsUpdate],
    sqs: [...regions, ...newRegionsUpdate],
    ssm: [...regions, ...newRegionsUpdate],
    shield: ['us-east-1'],
    sqs_encrypted: [...regions, ...newRegionsUpdate],
    sts: ['us-east-1'],
    transfer: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    lambda: [...regions, ...newRegionsUpdate],
    mwaa: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-south-1', 'eu-north-1', 'eu-central-1',
        'ap-southeast-2', 'ap-southeast-1', 'ap-northeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1'],
    directconnect: ['us-east-1'], // this is global service
    directoryservice: [...regions, ...newRegionsUpdate],
    efs: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    support: ['us-east-1'],
    wafregional: regions,
    wafv2: [...regions, ...newRegionsUpdate],
    waf: ['us-east-1'],
    organizations: ['us-east-1'],
    guardduty: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    workspaces: ['us-east-1', 'us-west-2', 'ca-central-1', 'sa-east-1', 'ap-south-1',
        'eu-west-1', 'eu-central-1', 'eu-west-2', 'ap-southeast-1',
        'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2', 'af-south-1'],
    servicequotas: [...regions, ...newRegionsUpdate],
    xray: [...regions, ...newRegionsUpdate],
    codestar: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-north-1'],
    codebuild: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    mq: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    glacier: regions,
    backup: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    elasticache: [...regions, ...newRegionsUpdate],
    timestreamwrite:  ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 'ap-southeast-2',
        'ap-northeast-1'],
    neptune: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'me-south-1', 'af-south-1', 'il-central-1','me-central-1'
    ],
    memorydb: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'eu-west-3', 'eu-south-1'],

    kafka: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'me-south-1', 'af-south-1', 'ap-south-2','ap-southeast-3', 'ap-northeast-3',
        'eu-central-2', 'me-central-1'],
    kendra:  ['us-east-1', 'us-east-2', 'us-west-2', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-west-1', 'ap-northeast-1', 'ap-south-1', 'eu-west-2'],
    proton: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-1', 'eu-west-1', 'eu-west-2', 'eu-central-1',
        'ca-central-1', 'ap-southeast-2', 'ap-southeast-1', 'ap-northeast-2'],
    customerprofiles: ['us-east-1', 'us-west-2', 'eu-west-2', 'ca-central-1', 'eu-central-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2'],
    qldb: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2'],
    finspace: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1','eu-west-1'],
    codepipeline: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    codeartifact: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'],
    auditmanager: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'
    ],
    appflow: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1','eu-west-3', 'sa-east-1', 'ap-northeast-2', 'af-south-1'
    ],
    translate: [
        'us-east-1', 'us-east-2', 'us-west-1','us-west-2', 'eu-west-1', 'eu-west-2', 'ap-northeast-2',
        'ap-east-1','af-south-1', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-west-3', 'eu-central-1',
        'eu-north-1'
    ],
    databrew: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'af-south-1'
    ],
    managedblockchain: ['us-east-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-northeast-1', 'eu-west-1', 'eu-west-2'],
    connect: ['us-east-1', 'us-west-2', 'eu-west-2', 'ca-central-1', 'eu-central-1',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'af-south-1'],
    apprunner:  ['us-east-1','us-east-2','us-west-2', 'eu-west-1','ap-northeast-1', 'eu-central-1', 'ap-southeast-2', 'ap-south-1',
        'ap-southeast-1', 'eu-west-2', 'eu-west-3'],
    healthlake: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-south-1'],
    lookoutequipment: ['us-east-1', 'eu-west-1', 'ap-northeast-2'],
    iotsitewise: ['us-east-1', 'us-west-2', 'ap-south-1', 'ap-southeast-1', 'ap-northeast-2', 'ap-southeast-2',
        'ap-northeast-1', 'eu-central-1', 'eu-west-1', 'ca-central-1', 'us-east-2'],
    location: [
        'us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 'eu-north-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'sa-east-1', 'eu-west-2', 'ca-central-1', 'ap-south-1'
    ],
    lookoutvision: ['us-east-1', 'us-east-2', 'ap-northeast-1',  'ap-northeast-2', 'eu-central-1', 'eu-west-1', 'us-west-2'],
    lookoutmetrics: ['us-east-1', 'us-east-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'eu-central-1',
        'eu-west-1', 'eu-north-1', 'us-west-2'],
    forecastservice: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1',
        'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'],
    lexmodelsv2: [ 'us-east-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'af-south-1'],
    fsx: [...regions, 'ap-south-2', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1'],
    wisdom: ['us-east-1', 'us-west-2', 'eu-west-2', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-2'],
    voiceid: ['us-east-1', 'us-west-2', 'eu-west-2', 'ca-central-1', 'eu-central-1',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'af-south-1'],
    appmesh:  [...regions, 'il-central-1'],
    frauddetector: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-southeast-2'],
    imagebuilder: [...regions, ...newRegionsUpdate],
    computeoptimizer: ['us-east-1'],
    appconfig: [...regions, ...newRegionsUpdate],
    opensearch: [...regions, ...newRegionsUpdate],
    opensearchserverless: ['us-east-2', 'us-east-1', 'us-west-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
        'eu-central-1', 'eu-west-1']
};
