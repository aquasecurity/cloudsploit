const expect = require('chai').expect;
var iamRolePolicies = require('./iamRolePolicies');


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
        "Path": "/service-role/",
            "RoleName": "test_lambda_core-role-04pqjctk",
            "RoleId": "AROASZ433I6EHK3RAK3E4",
            "Arn": "arn:aws:iam::123456789:role/service-role/test_lambda_core-role-04pqjctk",
            "CreateDate": "2022-11-08T10:04:57+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
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
                "PolicyName": "testPolicy",
                "PolicyArn": "arn:aws:iam::193063503752:policy/testPolicy"
            }
        ]
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
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22AWSCloudTrailCreateLogStream2014110%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22logs%3ACreateLogStream%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3Alogs%3Aus-east-1%3A193063503752%3Alog-group%3Aaws-cloudtrail-logs-193063503752-432bdd08%3Alog-stream%3A193063503752_CloudTrail_us-east-1%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22AWSCloudTrailPutLogEvents20141101%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22logs%3APutLogEvents%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3Alogs%3Aus-east-1%3A193063503752%3Alog-group%3Aaws-cloudtrail-logs-193063503752-432bdd08%3Alog-stream%3A193063503752_CloudTrail_us-east-1%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
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
    },
    {
        "Policy": {
            "PolicyName": "testPolicy",
            "PolicyId": "ANPASZ433I6ELDTSCKKP3",
            "Arn": "arn:aws:iam::123456789:policy/testPolicy",
            "Path": "/service-role/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 1,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "CreateDate": "2022-11-08T10:04:57+00:00",
            "UpdateDate": "2022-11-08T10:04:57+00:00",
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
            "Document": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AputObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ACreateFleet%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3As3%3A%3A%3A%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ACreateFleet%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3Aec2%3Aus-east-1%3A193063503752%3Ainstance%2F%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
            "VersionId": "v1",
            "IsDefaultVersion": true,
            "CreateDate": "2022-11-08T10:04:57+00:00"
        }
    }
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
                    "Value": "AquaCSPM"
                }
            ],
        }  
    },
    {
        "Role": {
            "Path": "/service-role/",
            "RoleName": "test_lambda_core-role-04pqjctk",
            "RoleId": "AROASZ433I6EHK3RAK3E4",
            "Arn": "arn:aws:iam::123456789:role/service-role/test_lambda_core-role-04pqjctk",
            "CreateDate": "2022-11-08T10:04:57+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "MaxSessionDuration": 3600,
            "RoleLastUsed": {}
        }
    
    }

];

const createCache = (listRoles,getRole, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion, listRolesErr, listRolePoliciesErr, listAttachedRolePoliciesErr) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    var policyArn = (listAttachedRolePolicies && listAttachedRolePolicies.AttachedPolicies) ? listAttachedRolePolicies.AttachedPolicies[0].PolicyArn : null;
    var policyName = (listRolePolicies && listRolePolicies.PolicyNames) ? listRolePolicies.PolicyNames[0] : null;
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: listRolesErr,
                    data: listRoles
                }
            },
            getRole: {
                'us-east-1': {
                    [roleName]:{   
                        data: getRole 
                    }              
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
            
        }
    };
};

const createNullCache = () => {
    return {
        lambda: {
            listRoles: {
                'us-east-1': null
            }
        }
    };
};

describe('iamRolePolicies', function () {
    describe('run', function () {

        it('should PASS if role does not have overly-permissive policy', function (done) {
            const cache = createCache([listRoles[0]], getRole[0], listAttachedRolePolicies[2], listRolePolicies[0], getRolePolicy[2]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Role does not have overly-permissive policy');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows wildcard actions', function (done) {
            const cache = createCache([listRoles[0]],getRole[0], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy allows wildcard actions');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore managed iam policies is set to true', function (done) {
            const cache = createCache([listRoles[0]],getRole[0], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            iamRolePolicies.run(cache, { ignore_customer_managed_iam_policies : 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on selected resources', function (done) {
            const cache = createCache([listRoles[0]],getRole[0], {}, listRolePolicies[1], getRolePolicy[4]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy allows all actions on selected resources');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on all resources', function (done) {
            const cache = createCache([listRoles[1]],getRole[0], {}, listRolePolicies[1], getRolePolicy[3]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy allows all actions on all resources');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore service specific roles setting is enabled', function (done) {
            const cache = createCache([listRoles[0]],getRole[0], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            iamRolePolicies.run(cache, { ignore_service_specific_wildcards: 'true'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if on IAM roles found', function (done) {
            const cache = createCache([]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No IAM roles found');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list IAM roles', function (done) {
            const cache = createCache(null, null, null, null, null, null, { message: 'Unable to list IAM roles'});
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for IAM roles');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([listRoles[1]],getRole[0], {}, null, null, null, null, null, null, { message: 'Unable to list attached role policies'});
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for IAM attached policy for role');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([listRoles[1]],getRole[0], listAttachedRolePolicies[0], {}, null, null, null, null, { message: 'Unable to query role policies'});
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for IAM role policy for role');
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list roles response not found', function (done) {
            const cache = createNullCache();
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should PASS if role with specific tag is ignored', function (done) {
            const cache = createCache([listRoles[0]],getRole[0], listAttachedRolePolicies[2], listRolePolicies[0], getRolePolicy[2]);
            iamRolePolicies.run(cache, {iam_role_policies_ignore_tag:'app_name:AquaCSPM'}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
       
        it('should FAIL if role policy allows resources which does not match regex in iam_policy_resource_specific_wildcards', function (done) {
            const cache = createCache([listRoles[2]],getRole[1], listAttachedRolePolicies[3], null, null, getPolicy[1], getPolicyVersion[1]);
            iamRolePolicies.run(cache, {ignore_service_specific_wildcards: 'true',iam_policy_resource_specific_wildcards: '^[a-z]+:[a-z]+:[a-z0-9]+:::[a-z]+$'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('policy does not match provided regex');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

    });
});