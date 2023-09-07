const expect = require('chai').expect;
var rolePolicyUnusedServices = require('./rolePolicyUnusedServices');


const listRoles = [
    {
        "Path": "/",
        "RoleName": "test-role-1",
        "RoleId": "AROAYE32SRU5VIMXXL3BH",
        "Arn": "arn:aws:iam::000011112222:role/test-role-1",
        "CreateDate": "2020-11-21T23:56:33Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::000011112222:root"
                    },
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {}
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-2",
        "RoleId": "AROAYE32SRU5VIMXXL3BH",
        "Arn": "arn:aws:iam::000011112222:role/test-role-2",
        "CreateDate": "2020-11-21T23:56:33Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::000011112222:root"
                    },
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {}
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-1",
        "RoleId": "AROAYE32SRU5VIMXXL3BH",
        "Arn": "arn:aws:iam::000011112222:role/test-role-1",
        "CreateDate": "2020-11-21T23:56:33Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::000011112222:root"
                    },
                    "Action": "ec2:DescribeTransitGatewayRouteTables",
                    "Condition": {}
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-3",
        "RoleId": "AROASZ433I6EC5DZRCA5R",
        "Arn": "arn:aws:iam::123456789:role/ecs-role",
        "CreateDate": "2022-11-25T12:29:26+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ecs.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Allows ECS to create and manage AWS resources on your behalf.",
        "MaxSessionDuration": 3600
    }
];

const listRolePolicies = [
    {
       "PolicyNames": [
           "S3-Full"
       ]
    },
    {
        "PolicyNames": [
            "All-Action-Resources"
        ]
    },
    {
        "PolicyNames": []
    }
];

const listAttachedRolePolicies = [
    {
        "ResponseMetadata": {
            "RequestId": 'f7d427cc-970b-47af-9b7d-3e06121f83da'
        },
        "AttachedPolicies": [
            {
                "PolicyName": 'AdministratorAccess',
                "PolicyArn": 'arn:aws:iam::aws:policy/AdministratorAccess'
            }
        ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'b06a66ed-53af-4737-b0d3-7ef9031d2c2e'
        },
        "AttachedPolicies": [
            {
                "PolicyName": 'EC2-Full',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/EC2-Full'
            }
        ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'b06a66ed-53af-4737-b0d3-7ef9031d2c2e'
        },
        "AttachedPolicies": [
            {
                "PolicyName": 'EC2-Wildcard',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/EC2-Wildcard'
            }
        ],
        "IsTruncated": false
    },
    {
        "AttachedPolicies": [
            {
                "PolicyName": "AmazonEC2ContainerServiceRole",
                "PolicyArn": "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole"
            }
        ]
    }
];

const getRolePolicy = [
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-Full',
        "PolicyDocument": [
            {
                Sid: 'VisualEditor0',
                Effect: 'Allow',
                Action: [ 's3:*' ],
                Resource: [ '*' ]
            }]
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-WildCard',
        "PolicyDocument": [
            {
                Sid: 'VisualEditor1',
                Effect: 'Allow',
                Action: [ 's3:g*' ],
                Resource: [ '*' ]
            }
        ]
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-Limited',
        "PolicyDocument": [
            {
                Sid: 'AWSCloudTrailCreateLogStream2014110',
                Effect: 'Allow',
                Action: [ 'logs:CreateLogStream' ],
                Resource: [ 'arn:aws:logs:us-east-1:193063503752:log-group:aws-cloudtrail-logs-193063503752-432bdd08:log-stream:193063503752_CloudTrail_us-east-1*' ]
            },
            {
                Sid: 'AWSCloudTrailPutLogEvents20141101',
                Effect: 'Allow',
                Action: [ 'logs:PutLogEvents' ],
                Resource: [ 'arn:aws:logs:us-east-1:193063503752:log-group:aws-cloudtrail-logs-193063503752-432bdd08:log-stream:193063503752_CloudTrail_us-east-1*' ]
            }]
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Action-Resources',
        "PolicyDocument": [
            {
                Sid: 'VisualEditor1',
                Effect: 'Allow',
                Action: [ '*' ],
                Resource: [ '*' ]
            }]
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Actions',
        "PolicyDocument": [
            {
                Sid: 'VisualEditor1',
                Effect: 'Allow',
                Action: [ '*' ],
                Resource: [ 'arn:aws:s3:::*' ]
            }]
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Actions',
        "PolicyDocument": [
            {
                Sid: 'VisualEditor0',
                Effect: 'Allow',
                Action: [ 's3:putObject', 'ec2:CreateFleet' ],
                Resource: [ 'arn:aws:s3:::*' ] },
            {
                Sid: 'VisualEditor1',
                Effect: 'Allow',
                Action: [ 'ec2:CreateFleet' ],
                Resource: [ 'arn:aws:ec2:us-east-1:193063503752:instance/*' ]
            }]
    }
];

const getPolicy = [
    {
        "Policy": {
            "PolicyName": 'EC2-Wildcard',
            "PolicyId": 'ANPAYE32SRU57UHNCIGCT',
            "Arn": 'arn:aws:iam::000011112222:policy/EC2-Wildcard',
            "Path": '/',
            "DefaultVersionId": 'v5',
            "AttachmentCount": 2,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true
        }
    },
    {
        "Policy": {
            "PolicyName": "AmazonEC2ContainerServiceRole",
            "PolicyId": "ANPAJO53W2XHNACG7V77Q",
            "Arn": "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole",
            "Path": "/service-role/",
            "DefaultVersionId": "v2",
            "AttachmentCount": 1,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "Description": "Default policy for Amazon ECS service role.",
            "CreateDate": "2015-04-09T16:14:19+00:00",
            "UpdateDate": "2016-08-11T13:08:01+00:00",
            "Tags": []
        }
    
    }
];

const getPolicyVersion = [
    {
        "PolicyVersion": {
            "Document": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3A%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3Aec2%3Aus-east-1%3A193063503752%3Ainstance%2Fi-0ed34b9c39ebd03ba%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
            "VersionId": 'v5',
        }
    },
    {
        "PolicyVersion": {
        "Document" : '%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22ec2%3AAuthorizeSecurityGroupIngress%22%2C%0A%20%20%20%20%20%20%20%20%22ec2%3ADescribe%2A%22%2C%0A%20%20%20%20%20%20%20%20%22elasticloadbalancing%3ADeregisterInstancesFromLoadBalancer%22%2C%0A%20%20%20%20%20%20%20%20%22elasticloadbalancing%3ADeregisterTargets%22%2C%0A%20%20%20%20%20%20%20%20%22elasticloadbalancing%3ADescribe%2A%22%2C%0A%20%20%20%20%20%20%20%20%22elasticloadbalancing%3ARegisterInstancesWithLoadBalancer%22%2C%0A%20%20%20%20%20%20%20%20%22elasticloadbalancing%3ARegisterTargets%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3Alogs%3Aus-east-1%3A193063503752%3Alog-group%3A%2Faws%2Flambda%2Ftest_lambda_core%3A%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
        "VersionId": 'v2',
    }
    }
];

const configStatus = [
    {
        name: 'default',
        lastStartTime: '2022-05-30T16:15:43.358Z',
        lastStopTime: '2022-05-30T16:12:18.651Z',
        recording: true,
        lastStatus: 'SUCCESS',
        lastStatusChangeTime: '2022-05-31T05:16:02.486Z'
    },
    {
        name: 'default',
        lastStartTime: '2022-05-30T16:15:43.358Z',
        lastStopTime: '2022-05-30T16:12:18.651Z',
        recording: false,
        lastStatus: 'SUCCESS',
        lastStatusChangeTime: '2022-05-31T05:16:02.486Z'
    },
    {
        name: 'default',
        lastStartTime: '2022-05-30T16:15:43.358Z',
        lastStopTime: '2022-05-30T16:12:18.651Z',
        recording: true,
        lastStatus: 'FAILURE',
        lastStatusChangeTime: '2022-05-31T05:16:02.486Z'
    }
];

const discoveredResources = [
    { resourceType: 'AWS::IAM::Role', count: 91 },
    { resourceType: 'AWS::IAM::Policy', count: 38 },
    { resourceType: 'AWS::KMS::Key', count: 28 },
    { resourceType: 'AWS::S3::Bucket', count: 19 },
    { resourceType: 'AWS::EC2::SecurityGroup', count: 17 },
    { resourceType: 'AWS::CodeDeploy::DeploymentConfig', count: 17 },
    { resourceType: 'AWS::IAM::User', count: 8 },
    { resourceType: 'AWS::EC2::Subnet', count: 8 },
    { resourceType: 'AWS::CloudFormation::Stack', count: 6 },
    { resourceType: 'AWS::CloudWatch::Alarm', count: 5 },
    { resourceType: 'AWS::Lambda::Function', count: 4 },
    { resourceType: 'AWS::EC2::RouteTable', count: 4 },
    { resourceType: 'AWS::SNS::Topic', count: 4 },
    { resourceType: 'AWS::EC2::VPC', count: 3 },
    { resourceType: 'AWS::EC2::NetworkInterface', count: 3 },
    { resourceType: 'AWS::ApiGateway::Stage', count: 3 },
    { resourceType: 'AWS::EC2::NetworkAcl', count: 3 },
    { resourceType: 'AWS::EC2::InternetGateway', count: 2 },
    { resourceType: 'AWS::AccessAnalyzer::Analyzer', count: 2 },
    { resourceType: 'AWS::CloudTrail::Trail', count: 2 },
    { resourceType: 'AWS::ApiGatewayV2::Stage', count: 2 },
    { resourceType: 'AWS::Backup::BackupVault', count: 2 },
    { resourceType: 'AWS::ApiGateway::RestApi', count: 2 },
    { resourceType: 'AWS::SQS::Queue', count: 1 },
    { resourceType: 'AWS::EC2::Instance', count: 1 },
    { resourceType: 'AWS::RDS::DBSubnetGroup', count: 1 },
    { resourceType: 'AWS::Redshift::ClusterParameterGroup', count: 1 },
    { resourceType: 'AWS::S3::AccountPublicAccessBlock', count: 1 },
    { resourceType: 'AWS::SecretsManager::Secret', count: 1 },
    { resourceType: 'AWS::RDS::DBSnapshot', count: 1 },
    { resourceType: 'AWS::EC2::LaunchTemplate', count: 1 },
    { resourceType: 'AWS::Redshift::ClusterSubnetGroup', count: 1 },
    { resourceType: 'AWS::RDS::DBSecurityGroup', count: 1 },
    { resourceType: 'AWS::CodeBuild::Project', count: 1 },
    { resourceType: 'AWS::ApiGatewayV2::Api', count: 1 },
    { resourceType: 'AWS::EC2::Volume', count: 1 },
    { resourceType: 'AWS::ECR::Repository', count: 1 }
];

const getRole = [
    {
        'Role':{
            "Path": "/",
            "RoleName": "test-role-1",
            "RoleId": "AROAYE32SRU5VIMXXL3BH",
            "Arn": "arn:aws:iam::000011112222:role/test-role-1",
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ],
        }  
    },
    {
        'Role':{
            "Path": "/",
            "RoleName": "test-role-1",
            "RoleId": "AROAYE32SRU5VIMXXL3BH",
            "Arn": "arn:aws:iam::000011112222:role/test-role-1",
            "Tags": [
            ],
        }  
    },
    {
        'Role':{
            "Path": "/",
            "RoleName": "test-role-2",
            "RoleId": "AROAYE32SRU5VIMXXL3BH",
            "Arn": "arn:aws:iam::000011112222:role/test-role-2",
            "Tags": [
            ],
        }  
    }

];

const createCache = (configStatus, discoveredResources, listRoles, getRole, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion, configStatusErr, discoveredResourcesErr, listRolesErr, listRolePoliciesErr, listAttachedRolePoliciesErr) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    var policyArn = (listAttachedRolePolicies && listAttachedRolePolicies.AttachedPolicies) ? listAttachedRolePolicies.AttachedPolicies[0].PolicyArn : null;
    var policyName = (listRolePolicies && listRolePolicies.PolicyNames) ? listRolePolicies.PolicyNames[0] : null;
    return {
        configservice: {
            describeConfigurationRecorderStatus: {
                'us-east-1': {
                    err: configStatusErr,
                    data: configStatus
                }
            },
            getDiscoveredResourceCounts: {
                'us-east-1': {
                    err: discoveredResourcesErr,
                    data: discoveredResources
                }
            }
        },
        iam: {
            listRoles: {
                'us-east-1': {
                    err: listRolesErr,
                    data: listRoles
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        err: listAttachedRolePoliciesErr,
                        data: listAttachedRolePolicies
                    }
                }
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        err: listRolePoliciesErr,
                        data: listRolePolicies
                    }
                }
            },
            getPolicy: {
                'us-east-1': {
                    [policyArn]: {
                        data: getPolicy
                    }
                }
            },
            getRolePolicy: {
                'us-east-1': {
                    [roleName]: {
                        [policyName]: {
                            data: getRolePolicy
                        }
                    }
                }
            },
            getPolicyVersion: {
                'us-east-1': {
                    [policyArn]: {
                        data: getPolicyVersion
                    }
                }
            },
            getRole: {
                'us-east-1': {
                    [roleName]: {
                        data: getRole
                    }
                }
            }
        }
    };
};

describe('rolePolicyUnusedServices', function () {
    describe('run', function () {
        it('should PASS if role does not have overly-permissive policy', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], listAttachedRolePolicies[2], listRolePolicies[0], getRolePolicy[2]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Role does not have overly-permissive policy');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows wildcard actions', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy allows wildcard actions');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore managed iam policies is set to true', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            rolePolicyUnusedServices.run(cache, { ignore_customer_managed_iam_policies : 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on selected resources', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], {}, listRolePolicies[1], getRolePolicy[4]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy allows all actions on selected resources');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on all resources', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[1]], getRole[1], {}, listRolePolicies[1], getRolePolicy[3]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy allows all actions on all resources');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore service specific roles setting is enabled', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            rolePolicyUnusedServices.run(cache, { ignore_service_specific_wildcards: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if np IAM roles found', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, []);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No IAM roles found');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list IAM roles', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, null, null, null, null, null, null, null,null,null, { message: 'Unable to list IAM roles'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for IAM roles');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[1]], getRole[1], {}, null, null, null, null, null, null, null, null, { message: 'Unable to list attached role policies'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for IAM attached policy for role:');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[1]], getRole[1], listAttachedRolePolicies[0], {}, null, null, null, null, null, null, { message: 'Unable to query role policies'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for IAM role policy for role');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if no unable to query for Config Service', function (done) {
            const cache = createCache(null, discoveredResources, [listRoles[1]], getRole[1], listAttachedRolePolicies[0], null, null, null, null, { message: 'Unable to query Config Service'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].message).to.include('Unable to query config service');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should FAIL if Config Service is not enabled', function (done) {
            const cache = createCache([], discoveredResources, [listRoles[1]], getRole[1], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].message).to.include('Config service is not enabled');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Config Service is not recording', function (done) {
            const cache = createCache([configStatus[1]], discoveredResources, [listRoles[1]], getRole[1], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].message).to.include('Config service is not recording');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Config Service is recording but not delivering properly', function (done) {
            const cache = createCache([configStatus[2]], discoveredResources, [listRoles[1]], getRole[1], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].message).to.include('Config Service is configured, and recording, but not delivering properly');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for Discovered Resources', function (done) {
            const cache = createCache([configStatus[0]], null, [listRoles[1]], getRole[1], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].message).to.include('Unable to query for Discovered Resources');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no Discovered Resources found', function (done) {
            const cache = createCache([configStatus[0]], [], [listRoles[1]], getRole[1], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No Discovered Resources found');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Role policies contain actions for resource types which are not in use', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[1], {}, listRolePolicies[1], getRolePolicy[4]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role with specific regex is ignored', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], {}, listRolePolicies[1], getRolePolicy[4]);
            rolePolicyUnusedServices.run(cache, {iam_role_policies_ignore_tag:'app_name:Aqua CSPM'}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should PASS if specific actions for service are ignored', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[3]], getRole[1], listAttachedRolePolicies[3], null, null,  getPolicy[1], getPolicyVersion[1]);
            rolePolicyUnusedServices.run(cache, {whitelist_unused_actions_for_resources: 'elasticloadbalancing:RegisterInstancesWithLoadBalancer, elasticloadbalancing:DeregisterInstancesFromLoadBalancer'}, (err,results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Role does not have overly-permissive');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows resources which does not match regex in iam_policy_resource_specific_wildcards', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], getRole[0], {}, listRolePolicies[1], getRolePolicy[5]);
            rolePolicyUnusedServices.run(cache, {ignore_service_specific_wildcards: 'true', iam_policy_resource_specific_wildcards: '^[a-z]+:[a-z]+:[a-z0-9]+:::[a-z]+$'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy does not match provided regex');
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
