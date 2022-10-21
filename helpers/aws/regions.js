// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'us-east-1',        // Northern Virginia
    'us-east-2',        // Ohio
    'us-west-1',        // Northern California
    'us-west-2',        // Oregon
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
    'ap-northeast-3',   // Asia Pacific (Osaka)
    'ap-south-1',       // Asia Pacific (Mumbai)
    'sa-east-1',        // South America (São Paulo)
    'ap-east-1',        // Asia Pacific (Hong Kong)
    'me-south-1',       // Middle East (Bahrain)
    'af-south-1'        // Africa (Cape Town)
];
var meCentral1 = [
    'me-central-1'
];

var newRegions = [
    'ap-southeast-3',   // Asia Pacific (Jakarta)
];


module.exports = {
    default: ['us-east-1'],
    all: [...regions, ...newRegions, ...meCentral1],
    optin: ['ap-east-1', 'me-south-1', 'ap-southeast-3'],   // Regions that AWS disables by default
    accessanalyzer: [...regions, ...newRegions],
    acm: [...regions, ...newRegions, ...meCentral1],
    apigateway: [...regions, ...newRegions, ...meCentral1],
    athena: regions,
    cloudfront: ['us-east-1'], // CloudFront uses the default global region
    autoscaling: [...regions, ...newRegions, ...meCentral1],
    iam: ['us-east-1'],
    route53: ['us-east-1'],
    route53domains: ['us-east-1'],
    s3: ['us-east-1'],
    s3control: ['us-east-1'],
    cloudformation: [...regions, ...newRegions, ...meCentral1],
    cloudtrail: [...regions, ...newRegions, ...meCentral1],
    cloudwatchlogs: [...regions, ...newRegions, ...meCentral1],
    comprehend: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1',
        'ap-southeast-2', 'ap-northeast-2', 'ap-south-1', 'ca-central-1'],
    configservice: [...regions, ...newRegions, ...meCentral1],
    dax: [...regions, ...newRegions, ...meCentral1],
    devopsguru: ['us-east-1', 'us-east-2', 'eu-west-1', 'eu-west-2', 'eu-west-3','ap-northeast-1', 'eu-central-1',
        'ap-southeast-1', 'ap-southeast-2', 'eu-north-1', 'ap-south-1', 'ap-northeast-2', 'ca-central-1','eu-central-1','sa-east-1'],
    dynamodb: [...regions, ...newRegions, ...meCentral1],
    docdb: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1'
    ],
    dlm: [...regions, ...newRegions, ...meCentral1],
    dms: [...regions, ...newRegions, ...meCentral1],
    ec2: [...regions, ...newRegions, ...meCentral1],
    ecr: [...regions, ...newRegions, ...meCentral1],
    eks: [...regions, ...newRegions],
    elasticbeanstalk: [...regions, ...newRegions],
    elastictranscoder: ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-south-1'],
    elb: [...regions, ...newRegions, ...meCentral1],
    elbv2: [...regions, ...newRegions, ...meCentral1],
    eventbridge: [...regions, ...newRegions, ...meCentral1],
    emr: [...regions, ...newRegions, ...meCentral1],
    es: [...regions, ...newRegions, ...meCentral1],
    glue: [...regions, ...newRegions],
    kinesis: [...regions, ...newRegions, ...meCentral1],
    kinesisvideo:  ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-northeast-1','ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'ap-east-1','sa-east-1'],
    firehose: [...regions, ...newRegions],
    kms: [...regions, ...newRegions, ...meCentral1],
    vpc: [...regions, ...newRegions, ...meCentral1],
    flowlogs: [...regions, ...newRegions, ...meCentral1],
    rds: [...regions, ...newRegions, ...meCentral1],
    redshift: [...regions, ...newRegions, ...meCentral1],
    cloudwatch: [...regions, ...newRegions, ...meCentral1],
    ecs: [...regions, ...newRegions, ...meCentral1],
    resourcegroupstaggingapi: [...regions, ...newRegions],
    sagemaker: [...regions, newRegions],
    secretsmanager: [...regions, ...newRegions, ...meCentral1],
    ses: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-3', 'ap-south-1',
        'sa-east-1', 'me-south-1', 'af-south-1'],
    sns: [...regions, ...newRegions, ...meCentral1],
    sqs: [...regions, ...newRegions, ...meCentral1],
    ssm: [...regions, ...newRegions, ...meCentral1],
    shield: ['us-east-1'],
    sqs_encrypted: [...regions, ...newRegions, ...meCentral1],
    sts: ['us-east-1'],
    transfer: regions,
    lambda: [...regions, ...newRegions, ...meCentral1],
    mwaa: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-south-1', 'eu-north-1', 'eu-central-1',
        'ap-southeast-2', 'ap-southeast-1', 'ap-northeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1'],
    directconnect: ['us-east-1'], // this is global service
    directoryservice: [...regions, ...newRegions],
    efs: [...regions, ...newRegions, ...meCentral1],
    support: ['us-east-1'],
    wafregional: regions,
    wafv2: regions,
    waf: ['us-east-1'],
    organizations: ['us-east-1'],
    guardduty: [...regions, ...newRegions, ...meCentral1],
    workspaces: ['us-east-1', 'us-west-2', 'ca-central-1', 'sa-east-1', 'ap-south-1',
        'eu-west-1', 'eu-central-1', 'eu-west-2', 'ap-southeast-1',
        'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2'],
    servicequotas: [...regions, ...newRegions],
    xray: [...regions, ...newRegions, ...meCentral1],
    codestar: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-north-1'],
    codebuild: [...regions, ...newRegions],
    mq: [...regions, ...newRegions],
    glacier: regions,
    backup: [...regions, ...newRegions],
    elasticache: [...regions, ...newRegions, ...meCentral1],
    timestreamwrite:  ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 'ap-southeast-2',
    'ap-northeast-1'],
    neptune: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'me-south-1'
    ],
    memorydb: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 
        'eu-west-1', 'eu-west-2', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1'],
    kafka: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'me-south-1', 'af-south-1'],
    kendra:  ['us-east-1', 'us-east-2', 'us-west-2', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-west-1'],
    proton: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-1', 'eu-west-1'],
    customerprofiles: ['us-east-1', 'us-west-2', 'eu-west-2', 'ca-central-1', 'eu-central-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2'],
    qldb: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2'],
    finspace: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1','eu-west-1'],
    codepipeline: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'ap-east-1',
        'sa-east-1'],
    codeartifact: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'],
    auditmanager: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'
    ],
    appflow: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2',
        'eu-west-3', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'af-south-1'
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
    apprunner:  ['us-east-1', 'us-west-2', 'us-west-2', 'eu-west-1','ap-northeast-1'],
    healthlake: ['us-east-1', 'us-east-2', 'us-west-2'],
    lookoutequipment: ['us-east-1', 'eu-west-1', 'ap-northeast-2'],
    iotsitewise: ['us-east-1', 'us-west-2', 'ap-south-1', 'ap-southeast-1', 'ap-northeast-2', 'ap-southeast-2',
        'ap-northeast-1', 'eu-central-1', 'eu-west-1', 'ca-central-1', 'us-east-2'],
    location: [
        'us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 'eu-north-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2'
    ],
    lookoutvision: ['us-east-1', 'us-east-2', 'ap-northeast-1',  'ap-northeast-2', 'eu-central-1', 'eu-west-1', 'us-west-2'],
    lookoutmetrics: ['us-east-1', 'us-east-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'eu-central-1',
        'eu-west-1', 'eu-north-1', 'us-west-2'],
    forecastservice: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 
        'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'],
    lexmodelsv2: [ 'us-east-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'af-south-1'],
    fsx: [...regions, ...newRegions],
    wisdom: ['us-east-1', 'us-west-2', 'eu-west-2', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-2'],
    voiceid: ['us-east-1', 'us-west-2', 'eu-west-2', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2'],
    appmesh:  [...regions, ...newRegions],
    frauddetector: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-southeast-2'],
    imagebuilder: [...regions, ...newRegions],
    computeoptimizer: ['us-east-1'],
    appconfig: [...regions, ...newRegions, ...meCentral1]
};
