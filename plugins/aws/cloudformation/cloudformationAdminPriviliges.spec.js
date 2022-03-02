const expect = require('chai').expect;
var cloudformationAdminPriviliges = require('./cloudformationAdminPriviliges');

const listStacks = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/aws-sam-cli-managed-default/b6136b70-6efd-11ec-b78c-0e81d5d55d65",
        "StackName": "aws-sam-cli-managed-default",
        "TemplateDescription": "Managed Stack for AWS SAM CLI",
        "CreationTime": "2022-01-06T14:34:10.262000+00:00",
        "LastUpdatedTime": "2022-01-06T14:34:27.009000+00:00",
        "StackStatus": "CREATE_COMPLETE",
        "DriftInformation": {
            "StackDriftStatus": "NOT_CHECKED"
        }
    },
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/sam-app/e26f50d0-6efd-11ec-bb7d-0e5217d78663",
        "StackName": "sam-app",
        "TemplateDescription": "S3 Uploader - sample application",
        "CreationTime": "2022-01-06T14:35:24.796000+00:00",
        "LastUpdatedTime": "2022-01-06T14:35:52.880000+00:00",
        "StackStatus": "CREATE_COMPLETE",
        "DriftInformation": {
            "StackDriftStatus": "NOT_CHECKED"
        }
    }
];

const describeStacks = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/aws-sam-cli-managed-default/b6136b70-6efd-11ec-b78c-0e81d5d55d65",
        "StackName": "aws-sam-cli-managed-default",
        "Description": "Managed Stack for AWS SAM CLI",
        "CreationTime": "2022-01-06T14:34:10.262000+00:00",
        "LastUpdatedTime": "2022-02-16T17:09:21.404000+00:00",
        "RollbackConfiguration": {
            "RollbackTriggers": []
        },
        "StackStatus": "UPDATE_COMPLETE",
        "DisableRollback": false,
        "NotificationARNs": [],
        "Outputs": [
            {
                "OutputKey": "SourceBucket",
                "OutputValue": "aws-sam-cli-managed-default-samclisourcebucket-10o2i0pvnvjml"
            }
        ],
        "RoleARN": "arn:aws:iam::000011112222:role/only-cf-role",
        "Tags": [
            {
                "Key": "ManagedStackSource",
                "Value": "AwsSamCli"
            }
        ],
        "EnableTerminationProtection": false,
        "DriftInformation": {
            "StackDriftStatus": "NOT_CHECKED"
        }
    },
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/sam-app/e26f50d0-6efd-11ec-bb7d-0e5217d78663",
        "StackName": "sam-app",
        "Description": "S3 Uploader - sample application",
        "CreationTime": "2022-01-06T14:35:24.796000+00:00",
        "LastUpdatedTime": "2022-02-16T16:36:23.291000+00:00",
        "RollbackConfiguration": {
            "RollbackTriggers": []
        },
        "StackStatus": "UPDATE_COMPLETE",
        "DisableRollback": true,
        "NotificationARNs": [],
        "Capabilities": [
            "CAPABILITY_IAM"
        ],
        "Outputs": [
            {
                "OutputKey": "APIendpoint",
                "OutputValue": "https://m9kyzunubc.execute-api.us-east-1.amazonaws.com",
                "Description": "HTTP API endpoint URL"
            },
            {
                "OutputKey": "S3UploadBucketName",
                "OutputValue": "sam-app-s3uploadbucket-ylnxiraqgwuq",
                "Description": "S3 bucket for application uploads"
            }
        ],
        "RoleARN": "arn:aws:iam::000011112222:role/mine1-cf",
        "Tags": [],
        "EnableTerminationProtection": false,
        "DriftInformation": {
            "StackDriftStatus": "NOT_CHECKED"
        }
    }
];

const listRoles = [
    {
        "Path": "/",
        "RoleName": "mine1-cf",
        "RoleId": "AROAYE32SRU55L7TD7HQ7",
        "Arn": "arn:aws:iam::000011112222:role/mine1-cf",
        "CreateDate": "2020-12-22T08:47:57Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudformation.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "only-cf-role",
        "RoleId": "AROAYE32SRU5UELB2F76P",
        "Arn": "arn:aws:iam::000011112222:role/only-cf-role",
        "CreateDate": "2020-12-25T09:09:48Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudformation.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    }
];

const listRolePolicies = [
    {
       "PolicyNames": [
           "EFS-Full"
       ]
    }
];

const listAttachedRolePolicies = [
    {
        "ResponseMetadata": {
            "RequestId": 'f6983e3d-4644-46d5-b55d-ca9290347b9f'
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
            "RequestId": '2fa46d77-1637-4c70-a8eb-7dc59993f359'
        },
        "AttachedPolicies": [
            {
                "PolicyName": 'only-cf-policy',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/only-cf-policy'
            }
        ],
        "IsTruncated": false
    }
];

const getRolePolicy = [
    {
        "RoleName": 'only-cf-role',
        "PolicyName": 'EFS-Full',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22elasticfilesystem%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    }
];

const getPolicy = [
    {
        "Policy": {
            "PolicyName": 'Allow_Manager_Role_Policy',
            "PolicyId": 'ANPAYE32SRU57UHNCIGCT',
            "Arn": 'arn:aws:iam::000011112222:policy/Allow_Manager_Role_Policy',
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
            "Document": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPoliciesGrantingServiceAccess%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListRoles%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroups%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor2%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Deny%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A000011112222%3Agroup%2F%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
            "VersionId": 'v5',
        }
    }
];

const createCache = (listStacks, describeStacks, listRoles, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion) => {
    var stackName = (listStacks && listStacks.length) ? listStacks[0].StackName : null;
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    var policyArn = (listAttachedRolePolicies && listAttachedRolePolicies.AttachedPolicies) ? listAttachedRolePolicies.AttachedPolicies[0].PolicyArn : null;
    var policyName = (listRolePolicies) ? listRolePolicies.PolicyNames[0] : null;

    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    data: listStacks
                }
            },
            describeStacks: {
                'us-east-1': {
                    [stackName]: {
                        data: {
                            "Stacks": [
                         describeStacks
                            ]   
                        }
                    }
                }
            }
        },
        iam: {
            listRoles: {
                'us-east-1': {
                    data: listRoles
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listAttachedRolePolicies
                    }
                }
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
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
                    [policyName]: {
                        data: getRolePolicy
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

const createErrorCache = () => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    err: {
                        message: 'error listing CloudFormation stacks'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': null
            }
        }
    };
};

describe('cloudformationAdminPriviliges', function () {
    describe('run', function () {
        it('should PASS if CloudFormation stack does not have admin privileges', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[0], [listRoles[1]], listAttachedRolePolicies[1], listRolePolicies[0], [getRolePolicy[0]]);
            cloudformationAdminPriviliges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CloudFormation stack has admin privileges', function (done) {
            const cache = createCache([listStacks[1]], describeStacks[1], [listRoles[0]], listAttachedRolePolicies[0], listRolePolicies[0], {}, getPolicy[0], [getPolicyVersion[0]]);
            cloudformationAdminPriviliges.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no CloudFormation stacks found', function (done) {
            const cache = createCache([]);
            cloudformationAdminPriviliges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list CloudFormation stacks', function (done) {
            const cache = createErrorCache();
            cloudformationAdminPriviliges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([listStacks[1]], describeStacks[0], [listRoles[1]], null);
            cloudformationAdminPriviliges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([listStacks[1]], describeStacks[0], [listRoles[1]], listAttachedRolePolicies[0], null);
            cloudformationAdminPriviliges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list CloudFormation stacks response not found', function (done) {
            const cache = createNullCache();
            cloudformationAdminPriviliges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
