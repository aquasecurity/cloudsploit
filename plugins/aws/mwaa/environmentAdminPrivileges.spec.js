const expect = require('chai').expect;
var environmentAdminPrivileges = require('./environmentAdminPrivileges');

const listEnvironments = [
    "env-1"
];

const getEnvironment = [
    {
        "Environment": {
            "Arn": "arn:aws:airflow:us-east-1:000011112222:environment/env-1",
            "ExecutionRoleArn": "arn:aws:iam::000011112222:role/service-role/AmazonMWAA-role-1",
            "Name": "env-1",
            "NetworkConfiguration": {
                "SecurityGroupIds": [
                    "sg-06bb33bc2a9d6cfa0",
                    "sg-0356a73d9749f97ad"
                ],
                "SubnetIds": [
                    "subnet-027b3e2dbd13be412",
                    "subnet-0ba3663b2ac3734d2"
                ]
            },
            "WebserverAccessMode": "PRIVATE_ONLY",
        }
    },
    {
        "Environment": {
            "Arn": "arn:aws:airflow:us-east-1:000011112222:environment/env-1",
            "ExecutionRoleArn": "arn:aws:iam::000011112222:role/service-role/AmazonMWAA-role-2",
            "Name": "env-1",
            "NetworkConfiguration": {
                "SecurityGroupIds": [
                    "sg-06bb33bc2a9d6cfa0",
                    "sg-0356a73d9749f97ad"
                ],
                "SubnetIds": [
                    "subnet-027b3e2dbd13be412",
                    "subnet-0ba3663b2ac3734d2"
                ]
            },
            "WebserverAccessMode": "PRIVATE_ONLY",
        }
    }
];

const listRoles = [
    {
        "Path": "/",
        "RoleName": "AmazonMWAA-role-1",
        "RoleId": "AROAYE32SRU55L7TD7HQ7",
        "Arn": "arn:aws:iam::000011112222:role/AmazonMWAA-role-1",
        "CreateDate": "2020-12-22T08:47:57Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "airflow.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "AmazonMWAA-role-2",
        "RoleId": "AROAYE32SRU5UELB2F76P",
        "Arn": "arn:aws:iam::000011112222:role/AmazonMWAA-role-2",
        "CreateDate": "2020-12-25T09:09:48Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "airflow.amazonaws.com"
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
                "PolicyName": 'Allow_Admin_Role_Policy',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/Allow_Admin_Role_Policy'
            }
        ],
        "IsTruncated": false
    }
];

const getRolePolicy = [
    {
        "RoleName": 'AmazonMWAA-role-2',
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


const createCache = (listEnvironments, getEnvironment, listRoles, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion) => {
    var envName = (listEnvironments && listEnvironments.length) ? listEnvironments[0] : null;
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    var policyArn = (listAttachedRolePolicies && listAttachedRolePolicies.AttachedPolicies) ? listAttachedRolePolicies.AttachedPolicies.PolicyArn : null;
    var policyName = (listRolePolicies) ? listRolePolicies.PolicyNames[0] : null;
    return {
        mwaa: {
            listEnvironments: {
                'us-east-1': {
                    data: listEnvironments
                }
            },
            getEnvironment: {
                'us-east-1': {
                    [envName]: {
                        data: getEnvironment
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
        mwaa: {
            listEnvironments: {
                'us-east-1': {
                    err: {
                        message: 'error listing Airflow environments'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        mwaa: {
            listEnvironments: {
                'us-east-1': null
            }
        }
    };
};

describe('environmentAdminPrivileges', function () {
    describe('run', function () {

        it('should PASS if environment does not have admin priveleges', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[0], [listRoles[0]], listAttachedRolePolicies[1], listRolePolicies[0], getRolePolicy[0]);
            environmentAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if environment has admin priveleges', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[1], [listRoles[1]], listAttachedRolePolicies[0], listRolePolicies[0], {}, getPolicy[0], getPolicyVersion[0]);
            environmentAdminPrivileges.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Airflow environments found', function (done) {
            const cache = createCache([]);
            environmentAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Airflow environments', function (done) {
            const cache = createErrorCache();
            environmentAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[0], [listRoles[1]], null);
            environmentAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[0], [listRoles[1]], listAttachedRolePolicies[0], null);
            environmentAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list Airflow environments response not found', function (done) {
            const cache = createNullCache();
            environmentAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});