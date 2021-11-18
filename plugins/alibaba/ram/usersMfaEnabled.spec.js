var expect = require('chai').expect;
var usersMfaEnabled = require('./usersMfaEnabled')

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

const getUserMfa = [
    {
        "MFADevice": {
          "Type": "VMFA",
          "SerialNumber": "acs:ram::0000111122223333:mfa/aqua"
        }
    },
    {
        code: "EntityNotExist.User.MFADevice"
    }
];

const createCache = (users, userMfaInfo, usersErr, userMfaInfoErr) => {
    let userName = (users && users.length) ? users[0].UserName : null;
    return {
        ram: {
            ListUsers: {
                'cn-hangzhou': {
                    data: users,
                    err: usersErr
                }
            },
            GetUserMFAInfo: {
                'cn-hangzhou': {
                    [userName]: {
                        data: userMfaInfo,
                        err: userMfaInfoErr
                    }
                }
            }
        }
    }
}

describe('usersMfaEnabled', function () {
    describe('run', function () {
        it('should FAIL if RAM user does not have MFA device configured', function (done) {
            const cache = createCache([listUsers[1]], null, null, getUserMfa[1]);
            usersMfaEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RAM user does not have MFA device configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if RAM user has MFA device configured', function (done) {
            const cache = createCache([listUsers[0]], getUserMfa[0]);
            usersMfaEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RAM user has MFA device configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No RAM users found', function (done) {
            const cache = createCache([]);
            usersMfaEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RAM users found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query RAM users', function (done) {
            const cache = createCache([], null, { err: 'Unable to query RAM users' });
            usersMfaEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM users');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})
