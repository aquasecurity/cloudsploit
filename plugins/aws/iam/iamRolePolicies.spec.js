const expect = require('chai').expect;
const iamRolePolicies = require('./iamRolePolicies');

const listRoles = [
    {
        "Path": "/",
        "RoleName": "iam-role-1",
        "RoleId": "AROAYE32SRU5TQY4O5JBW",
        "Arn": "arn:aws:iam::111122223333:role/iam-role-1",
        "CreateDate": "2020-12-02T06:34:08.000Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22iam.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Iam role.",
        "MaxSessionDuration": 3600,
        "Tags": []
    },
    {
        "Path": "/",
        "RoleName": "iam-role-2",
        "RoleId": "AROAYE32SRU5R232MB5LZ",
        "Arn": "arn:aws:iam::111122223333:role/iam-role-2",
        "CreateDate": "2020-11-30T07:58:42.000Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22iam.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Iam role",
        "MaxSessionDuration": 3600,
        "Tags": []
    },
    {
        "Path": "/",
        "RoleName": "iam-role-3",
        "RoleId": "AROAYE32SRU5R232MB5LZ",
        "Arn": "arn:aws:iam::111122223333:role/iam-role-3",
        "CreateDate": "2020-11-30T07:58:42.000Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22iam.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Iam role",
        "MaxSessionDuration": 3600,
        "Tags": []
    },
    {
        "Path": "/",
        "RoleName": "iam-role-4",
        "RoleId": "AROAYE32SRU5R232MB5LZ",
        "Arn": "arn:aws:iam::111122223333:role/iam-role-4",
        "CreateDate": "2020-11-30T07:58:42.000Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22iam.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Iam role",
        "MaxSessionDuration": 3600,
        "Tags": []
    }
];

const listRolePolicies = [
    {
        "ResponseMetadata": { 
            "RequestId": '32c83dc4-bbdb-4b20-b9b7-b461a6942e04'
        },
        "PolicyNames": [ 'test1-role-policy' ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'ecfb7061-b67c-47de-afe4-e5505bb17a97'
        },
        "PolicyNames": [ 'test2-role-policy' ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'ecfb7061-b67c-47de-afe4-e5505bb17a97'
        },
        "PolicyNames": [ 'test3-role-policy' ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'ecfb7061-b67c-47de-afe4-e5505bb17a97'
        },
        "PolicyNames": [ 'test4-role-policy' ],
        "IsTruncated": false
    }
];

const getRolePolicy = [
    {
        "test1-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'iam-role-1',
                "PolicyName": 'test1-role-policy',
                "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3As3%3A%3A%3Aperm-data%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
            }
        }
    },
    {
        "test2-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'iam-role-2',
                "PolicyName": 'test2-role-policy',
                "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3As3%3A%3A%3Aperm-data%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
            }
        }
    },
    {
        "test3-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'iam-role-3',
                "PolicyName": 'test3-role-policy',
                "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
            }
        }
    },
    {
        "test4-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'iam-role-3',
                "PolicyName": 'test3-role-policy',
                "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3AGetRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3As3%3A%3A%3Aperm-data%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
            }
        }
    }
];

const listAttachedRolePolicies = [
    {
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
        ]
    },
    {
        "AttachedPolicies": []
    }
];

const createCache = (listRoles, listRolePolicies, getRolePolicy, listAttachedRolePolicies) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: listRoles,
                },
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listRolePolicies
                    }
                }
            },
            getRolePolicy: {
                'us-east-1': {
                    [roleName]: getRolePolicy
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listAttachedRolePolicies
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': null,
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM users'
                    },
                },
            },
        },
    };
};

describe('iamRolePolicies', function () {
    describe('run', function () {

        it('should FAIL if role has managed AdministratorAccess policy', function (done) {
            const cache = createCache([listRoles[2]], [], [], listAttachedRolePolicies[0]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role inline policy allows all actions on all resources', function (done) {
            const cache = createCache([listRoles[2]], listRolePolicies[2], getRolePolicy[2], []);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role inline policy allows all actions on selected resources', function (done) {
            const cache = createCache([listRoles[1]], listRolePolicies[1], getRolePolicy[1], []);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role inline policy allows wildcard actions', function (done) {
            const cache = createCache([listRoles[0]], listRolePolicies[0], getRolePolicy[0], []);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role does not have overly-permissive policy', function (done) {
            const cache = createCache([listRoles[3]], listRolePolicies[3], getRolePolicy[3], []);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no IAM users found', function (done) {
            const cache = createCache([]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if uanble to list IAM users', function (done) {
            const cache = createErrorCache();
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list IAM users response not found', function (done) {
            const cache = createNullCache();
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});