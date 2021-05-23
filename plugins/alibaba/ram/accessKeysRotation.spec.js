var expect = require('chai').expect;
var accessKeysRotation = require('./accessKeysRotation')

const listUsers = [
    {
        "UserName": "aqua",
        "UserId": "254529020129829608",
    },
    {
        "UserName": "cloudsploit",
        "UserId": "283806919721151694",
    }
];

const getUserLoginProfile = [
    {
        AccessKeys: {
            AccessKey: [
              {
                Status: "Active",
                AccessKeyId: "LTAI5tD6ekrSssrWq5rNa4JQ",
                CreateDate: "2021-01-11T16:37:58Z",
              },
            ],
        },
    },
    {
        AccessKeys: {
            AccessKey: [
              {
                Status: "Active",
                AccessKeyId: "LTAI5tD6ekrSssrWq5rNa4JQ",
                CreateDate: "2021-05-11T16:37:58Z",
              },
            ],
        },
    },
    {
        AccessKeys: {
            AccessKey: [
              {
              },
            ],
        },
    }
];

const createCache = (users, accessKeys, error) => {
    let userName = (users && users.length) ? users[0].UserName : null;
    return {
        ram: {
            ListUsers: {
                'cn-hangzhou': {
                    data: users,
                    err: error
                }
            },
            ListAccessKeys: {
                'cn-hangzhou': {
                    [userName]: {
                        data: accessKeys,
                        err: error
                    }
                }
            },
        }
    }
}

describe('accessKeysRotation', function () {
    describe('run', function () {
        it('should FAIL if RAM user access keys are not rotated every 90 days or less', function (done) {
            const cache = createCache([listUsers[0]], getUserLoginProfile[0], null);
            accessKeysRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RAM user access keys are not rotated every 90 days or less');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RAM user access keys are not rotated every 90 days or less', function (done) {
            const cache = createCache([listUsers[0]], getUserLoginProfile[1], null);
            accessKeysRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RAM user access keys are rotated every 90 days or less');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RAM user access keys does not exist', function (done) {
            const cache = createCache([listUsers[1]], getUserLoginProfile[2], null);
            accessKeysRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RAM user access keys does not exist');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No RAM users found', function (done) {
            const cache = createCache([]);
            accessKeysRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RAM users found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query RAM users', function (done) {
            const cache = createCache(null, null, null);
            accessKeysRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM users');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})