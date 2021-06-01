var expect = require('chai').expect;
var ramPolicyAttachments = require('./ramPolicyAttachments')

const listUsers = [
    {
        "UpdateDate": "2021-05-04T12:03:49Z",
        "UserName": "aqua",
        "Comments": "",
        "UserId": "254529020129829608",
        "DisplayName": "aqua",
        "CreateDate": "2021-05-04T12:03:49Z"
    },
    {
        "UpdateDate": "2021-05-04T09:54:39Z",
        "UserName": "cloudsploit",
        "Comments": "",
        "UserId": "283806919721151694",
        "DisplayName": "cloudsploit",
        "CreateDate": "2021-04-29T18:32:31Z"
    }
];

const listPoliciesForUser = [
    {
        "Policies": {
            "Policy": [
                {
                    "PolicyType": "System",
                    "Description": "管理所有阿里云资源的权限",
                    "AttachDate": "2021-04-29T18:33:41Z",
                    "PolicyName": "AdministratorAccess",
                    "DefaultVersion": "v1"
                }
            ]
        },
        "RequestId": "BF73EF1D-B99D-4B55-A9C1-C130FCEA40DA"
    },
    {
        "Policies": {
            "Policy": []
        },
    }
]

const createCache = (users, listPolicies, usersErr, listPoliciesErr) => {
    let userName = (users && users.length) ? users[0].UserName : null;
    return {
        ram: {
            ListUsers: {
                'cn-hangzhou': {
                    data: users,
                    err: usersErr
                }
            },
            ListPoliciesForUser: {
                'cn-hangzhou': {
                    [userName]: {
                        data: listPolicies,
                        err: listPoliciesErr
                    }
                }
            }
        }
    }
}

describe('ramPolicyAttachments', function () {
    describe('run', function () {
        it('should FAIL if User has policies attached', function (done) {
            const cache = createCache([listUsers[1]], listPoliciesForUser[0]);
            ramPolicyAttachments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('User has 1 policy(s) attached');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no policies are attached to user', function (done) {
            const cache = createCache([listUsers[0]], listPoliciesForUser[1]);
            ramPolicyAttachments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No policies are attached to user');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No RAM users found', function (done) {
            const cache = createCache([]);
            ramPolicyAttachments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RAM users found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query RAM users', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RAM users' });
            ramPolicyAttachments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM users');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})
