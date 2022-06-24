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
    }
];

const getRolePolicy = [
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-Full',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-WildCard',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3Ag%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-Limited',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3AGetObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D' 
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Action-Resources',
        "PolicyDocument":'%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Actions',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3As3%3A%3A%3A%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
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
    }
];

const getPolicyVersion = [
    {
        "PolicyVersion": {
            "Document": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3Ag%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
            "VersionId": 'v5',
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

const createCache = (configStatus, discoveredResources, listRoles, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion, configStatusErr, discoveredResourcesErr, listRolesErr, listRolePoliciesErr, listAttachedRolePoliciesErr) => {
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
            }
        }
    };
};

describe('rolePolicyUnusedServices', function () {
    describe('run', function () {
        it('should PASS if role does not have overly-permissive policy', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], listAttachedRolePolicies[2], listRolePolicies[0], getRolePolicy[2]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows wildcard actions', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore managed iam policies is set to true', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            rolePolicyUnusedServices.run(cache, { ignore_customer_managed_iam_policies : 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on selected resources', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], {}, listRolePolicies[1], getRolePolicy[4]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on all resources', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[1]], {}, listRolePolicies[1], getRolePolicy[3]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore service specific roles setting is enabled', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            rolePolicyUnusedServices.run(cache, { ignore_service_specific_wildcards: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if on IAM roles found', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, []);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list IAM roles', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, null, null, null, null, null, null, null, null, { message: 'Unable to list IAM roles'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[1]], {}, null, null, null, null, null, null, null, null, { message: 'Unable to list attached role policies'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[1]], listAttachedRolePolicies[0], {}, null, null, null, null, null, null, { message: 'Unable to query role policies'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if no unable to query for Config Service', function (done) {
            const cache = createCache(null, discoveredResources, [listRoles[1]], listAttachedRolePolicies[0], null, null, null, null, { message: 'Unable to query Config Service'});
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should FAIL if Config Service is not enabled', function (done) {
            const cache = createCache([], discoveredResources, [listRoles[1]], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Config Service is not recording', function (done) {
            const cache = createCache([configStatus[1]], discoveredResources, [listRoles[1]], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Config Service is recording but not delivering properly', function (done) {
            const cache = createCache([configStatus[2]], discoveredResources, [listRoles[1]], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UKNOWN if unable to query for Discovered Resources', function (done) {
            const cache = createCache([configStatus[0]], null, [listRoles[1]], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no Discovered Resources found', function (done) {
            const cache = createCache([configStatus[0]], [], [listRoles[1]], listAttachedRolePolicies[0]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Role policies contain actions for resource types which are not in use', function (done) {
            const cache = createCache([configStatus[0]], discoveredResources, [listRoles[0]], {}, listRolePolicies[1], getRolePolicy[4]);
            rolePolicyUnusedServices.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
