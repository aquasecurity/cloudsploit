var expect = require('chai').expect;
var ramAdminPolicy = require('./ramAdminPolicy')

const listPolicies = [
    {
        "UpdateDate": "2021-09-21T09:16:47Z",
        "PolicyType": "Custom",
        "Description": "",
        "AttachmentCount": 0,
        "DefaultVersion": "v1",
        "PolicyName": "ECSFullAccess",
        "CreateDate": "2021-09-21T09:16:47Z"
    },
    {
        "UpdateDate": "2021-09-22T08:44:56Z",
        "PolicyType": "Custom",
        "Description": "",
        "AttachmentCount": 0,
        "DefaultVersion": "v3",
        "PolicyName": "adminPolicy",
        "CreateDate": "2021-09-22T08:43:10Z"
    },
    {
        "UpdateDate": "2017-04-27T16:48:07Z",
        "PolicyType": "System",
        "Description": "管理所有阿里云资源的权限",
        "AttachmentCount": 8,
        "DefaultVersion": "v1",
        "PolicyName": "AdministratorAccess",
        "CreateDate": "2015-04-28T16:15:44Z"
    },
];

const getPolicy = [
    {
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "PolicyDocument": "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"ecs:*\"],\"Resource\":[\"*\"],\"Condition\":{}}]}",
        "CreateDate": "2021-09-21T09:16:47Z"
    },
    {
        
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "PolicyDocument": "\n{\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ],\n  \"Version\": \"1\"\n}\n                        ",
        "CreateDate": "2015-04-28T16:15:44Z"
    },
    {
        "VersionId": "v3",
        "IsDefaultVersion": true,
        "PolicyDocument": "{\n    \"Statement\": [\n        {\n            \"Action\": \"*\",\n            \"Effect\": \"Allow\",\n            \"Resource\": \"*\"\n        }\n    ],\n    \"Version\": \"1\"\n}",
        "CreateDate": "2021-09-22T08:44:56Z"
    }
]

const createCache = (listPolicies, getPolicy, listPoliciesErr, getPolicyErr) => {
    let policyName = (listPolicies && listPolicies.length) ? listPolicies[0].PolicyName : null;
    return {
        ram: {
            ListPolicies: {
                'cn-hangzhou': {
                    data: listPolicies,
                    err: listPoliciesErr
                }
            },
            GetPolicy: {
                'cn-hangzhou': {
                    [policyName]: {
                        data: getPolicy,
                        err: getPolicyErr
                    }
                }
            }
        }
    }
}

describe('ramAdminPolicy', function () {
    describe('run', function () {
        it('should FAIL if Policy provides admin (*:*) access and attachment count is greater than 0', function (done) {
            const cache = createCache([listPolicies[2]], getPolicy[1]);
            ramAdminPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Policy provides admin (*:*) access and attachment count is');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Policy provides admin (*:*) access but attachment count is 0', function (done) {
            const cache = createCache([listPolicies[1]], getPolicy[2]);
            ramAdminPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Policy provides admin (*:*) access but attachment count is 0');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Policy does not provide admin (*:*) access', function (done) {
            const cache = createCache([listPolicies[0]], getPolicy[0]);
            ramAdminPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Policy does not provide admin (*:*) access');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No RAM policies found', function (done) {
            const cache = createCache([]);
            ramAdminPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RAM policies found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query RAM policies', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RAM policies' });
            ramAdminPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM policies');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to get RAM policy', function (done) {
            const cache = createCache([listPolicies[1]], {}, null, {err: 'Unable to query RAM policy'});
            ramAdminPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get RAM policy');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})
