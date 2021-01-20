var expect = require('chai').expect;
const crossAccountMfaExtIdAccess = require('./crossAccountMfaExtIdAccess');

const roles = [
    {
        "Path": "/aws-service-role/support.amazonaws.com/",
        "RoleName": "AWSServiceRoleForSupport",
        "RoleId": "AROAYE32SRU57FHIKLZI5",
        "Arn": "arn:aws:iam::123456654321:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
        "CreateDate": "2020-08-09T16:55:28Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22trustedadvisor.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Enables resource access for AWS to provide billing, administrative and support services",
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-MFA-true",
        "RoleId": "AROAYE32SRU5VULODBGFK",
        "Arn": "arn:aws:iam::123456654321:role/test-role-MFA-true",
        "CreateDate": "2020-08-30T17:48:45Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456654321%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%2C%22Condition%22%3A%7B%22Bool%22%3A%7B%22aws%3AMultiFactorAuthPresent%22%3A%22true%22%7D%7D%7D%5D%7D",
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-web-identity",
        "RoleId": "AROAYE32SRU52CTP2RVNS",
        "Arn": "arn:aws:iam::123456654321:role/test-role-web-identity",
        "CreateDate": "2020-08-30T17:55:56Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Federated%22%3A%22graph.facebook.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRoleWithWebIdentity%22%2C%22Condition%22%3A%7B%22StringEquals%22%3A%7B%22graph.facebook.com%3Aapp_id%22%3A%22test-id%22%7D%7D%7D%5D%7D",
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-external-id",
        "RoleId": "AROAYE32SRU52JAKJR5YY",
        "Arn": "arn:aws:iam::123456654321:role/test-role-external-id",
        "CreateDate": "2020-08-30T21:18:35Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456654321%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%2C%22Condition%22%3A%7B%22StringEquals%22%3A%7B%22sts%3AExternalId%22%3A%2212345%22%7D%7D%7D%5D%7D",
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-MFA-externalid-false",
        "RoleId": "AROAYE32SRU5ZCTFXUN6O",
        "Arn": "arn:aws:iam::123456654321:role/test-role-MFA-externalid-false",
        "CreateDate": "2020-08-30T19:09:22Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456654321%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%2C%22Condition%22%3A%7B%7D%7D%5D%7D",
        "MaxSessionDuration": 3600
    }
];

const createCache = (roles) => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: roles,
                },
            },
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM roles'
                    },
                },
            },
        },
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

describe('crossAccountMfaExtIdAccess', function () {
    describe('run', function () {
        it('should FAIL if cross-account role does not require MFA/external ID for any account', function (done) {
            const cache = createCache([roles[4]]);
            crossAccountMfaExtIdAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if cross-account role requires MFA/external ID for all accounts', function (done) {
            const cache = createCache([roles[1], roles[3]]);
            crossAccountMfaExtIdAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no IAM roles found', function (done) {
            const cache = createCache([]);
            crossAccountMfaExtIdAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no cross-account IAM role found', function (done) {
            const cache = createCache([roles[0], roles[2]]);
            crossAccountMfaExtIdAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0)
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for IAM roles', function (done) {
            const cache = createErrorCache();
            crossAccountMfaExtIdAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for IAM roles', function (done) {
            const cache = createNullCache();
            crossAccountMfaExtIdAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});